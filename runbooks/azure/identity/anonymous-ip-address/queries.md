# Query Reference - Anonymous IP Address Sign-In (RB-0004)

> **Author:** Samet (KQL Engineer)
> **Reviewed by:** Hasan (Platform Architect), Alp (QA Lead)
> **Version:** 1.0
> **Date:** 2026-02-22

## Query Inventory

| # | Query | Step | Tables | Purpose | Estimated Runtime | Required |
|---|---|---|---|---|---|---|
| 1 | Extract Risk Event + Sign-In | Step 1 | AADUserRiskEvents, SigninLogs | Extract anonymizedIPAddress risk event and matching sign-in | <5s | Yes |
| 2 | Anonymous IP Classification | Step 2 | SigninLogs, ThreatIntelligenceIndicator | Classify anonymous IP type (Tor/VPN/proxy) | <5s | Yes |
| 3 | Sign-In Baseline (30-day) | Step 3 | SigninLogs | Establish normal sign-in pattern for anomaly comparison | 5-10s | MANDATORY |
| 4 | Session Analysis | Step 4 | SigninLogs | Sign-in session analysis from anonymous IP | <5s | Yes |
| 5 | Non-Interactive Sign-Ins | Step 5 | AADNonInteractiveUserSignInLogs | Non-interactive sign-ins from anonymous IP | <5s | Yes |
| 6A | Directory Changes | Step 6 | AuditLogs | Post-sign-in persistence detection | <5s | Yes |
| 6B | Email/File Activity | Step 6 | OfficeActivity | Post-sign-in email and file access | 5-10s | Yes |
| 6C | Inbox Rule Deep Dive | Step 6 | OfficeActivity | Inbox rule parameter extraction | <5s | Yes |
| 7A | TI Lookup | Step 7 | ThreatIntelligenceIndicator | IP reputation (TI feeds) | <3s | Optional |
| 7B | Org IP Usage | Step 7 | SigninLogs | Organizational IP usage check | 5-10s | Yes |

## Input Parameters

All queries in this runbook use the following shared input parameters. Replace these values with the actual alert data before running.

```kql
// ============================================================
// SHARED INPUT PARAMETERS - Set these before running any query
// ============================================================
let targetUser = "user@contoso.com";          // UserPrincipalName from the alert
let alertTime = datetime(2026-02-22T10:15:00Z); // TimeGenerated of the risk event
let alertIP = "185.220.101.34";               // Source IP from the risk event (anonymous IP)
```

---

## Query 1: Extract Risk Event and Sign-In Details

**Purpose:** Pull the complete risk event and matching sign-in record that triggered the anonymous IP alert. Understand the full authentication context and confirm the risk event type is `anonymizedIPAddress`.

**Tables:** AADUserRiskEvents, SigninLogs

**Investigation Step:** Step 1

### Production Query

```kql
// ============================================================
// Query 1: Extract Risk Event and Sign-In Details
// Purpose: Pull the risk event and full sign-in context for the
//          "Anonymous IP address" alert
// Tables: AADUserRiskEvents, SigninLogs
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-22T10:15:00Z);
let alertIP = "185.220.101.34";
// Lookback window around the alert time to catch the matching sign-in
let lookbackWindow = 2h;
// --- Part 1: Get the risk event ---
// Note: IpAddress uses capital 'A' in AADUserRiskEvents (not IPAddress)
let riskEvent = AADUserRiskEvents
    | where TimeGenerated between ((alertTime - lookbackWindow) .. (alertTime + lookbackWindow))
    | where UserPrincipalName == targetUser
    | where RiskEventType == "anonymizedIPAddress"
    | where IpAddress == alertIP
    | project
        RiskTimeGenerated = TimeGenerated,
        UserPrincipalName,
        RiskEventType,
        RiskLevel,
        RiskState,
        DetectionTimingType,
        RiskIpAddress = IpAddress,
        RiskLocation = Location,
        CorrelationId,
        Id;
// --- Part 2: Get the full sign-in record ---
// Note: IPAddress uses capital 'IP' in SigninLogs (not IpAddress)
let signinDetails = SigninLogs
    | where TimeGenerated between ((alertTime - lookbackWindow) .. (alertTime + lookbackWindow))
    | where UserPrincipalName == targetUser
    | project
        SigninTimeGenerated = TimeGenerated,
        UserPrincipalName,
        IPAddress,
        Location,
        // DeviceDetail is dynamic - use tostring() for nested fields
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
        // MfaDetail can be empty if MFA was not performed (Hasan's gotcha)
        MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "No MFA performed"),
        MfaAuthDetail = iff(isnotempty(MfaDetail), tostring(MfaDetail.authDetail), ""),
        ConditionalAccessStatus,
        // ResultType is a STRING, not int (Hasan's gotcha)
        ResultType,
        ResultDescription = iff(ResultType == "0", "Success", ResultType),
        CorrelationId,
        SessionId;
// --- Combine risk event with sign-in details ---
riskEvent
| join kind=inner signinDetails on CorrelationId, UserPrincipalName
| project
    // Risk event context
    RiskTimeGenerated,
    DetectionTimingType,
    RiskLevel,
    RiskState,
    RiskEventType,
    // User identity
    UserPrincipalName,
    // Source context
    IPAddress,
    LocationCity = tostring(Location.city),
    LocationCountry = tostring(Location.countryOrRegion),
    // Device context
    DeviceOS,
    DeviceBrowser,
    DeviceIsCompliant,
    DeviceIsManaged,
    DeviceTrustType,
    UserAgent,
    // Application context
    AppDisplayName,
    ResourceDisplayName,
    ClientAppUsed,
    // Authentication context
    AuthenticationRequirement,
    MfaAuthMethod,
    MfaAuthDetail,
    ConditionalAccessStatus,
    // Sign-in result
    ResultType,
    ResultDescription,
    // Tracking IDs
    CorrelationId,
    SessionId,
    SigninTimeGenerated
| order by RiskTimeGenerated desc
```

### Expected Output Columns

| Column | Type | Description |
|---|---|---|
| RiskTimeGenerated | datetime | When the risk event was generated |
| DetectionTimingType | string | "realtime" or "offline" - realtime is higher confidence |
| RiskLevel | string | "low", "medium", "high" |
| RiskState | string | Current risk state (atRisk, confirmedCompromised, dismissed, etc.) |
| RiskEventType | string | Should be "anonymizedIPAddress" |
| UserPrincipalName | string | Affected user |
| IPAddress | string | Source anonymous IP of the sign-in |
| LocationCity | string | City extracted from Location dynamic (often empty for anonymous IPs) |
| LocationCountry | string | Country extracted from Location dynamic |
| DeviceOS | string | Operating system of the device |
| DeviceBrowser | string | Browser used |
| DeviceIsCompliant | string | "true"/"false" - Intune compliance |
| DeviceIsManaged | string | "true"/"false" - managed device |
| DeviceTrustType | string | Trust type (e.g., "AzureAd", "Workplace") |
| UserAgent | string | Raw user agent string - check for Tor Browser fingerprint |
| AppDisplayName | string | Application accessed |
| ResourceDisplayName | string | Target resource |
| ClientAppUsed | string | Client type (Browser, Mobile Apps, etc.) |
| AuthenticationRequirement | string | "singleFactorAuthentication" or "multiFactorAuthentication" |
| MfaAuthMethod | string | MFA method or "No MFA performed" |
| MfaAuthDetail | string | MFA detail or empty |
| ConditionalAccessStatus | string | "success", "failure", "notApplied" |
| ResultType | string | "0" = success, other = failure code |
| ResultDescription | string | Human-readable result |
| CorrelationId | string | Event correlation GUID |
| SessionId | string | Session identifier |
| SigninTimeGenerated | datetime | Sign-in timestamp |

### Performance Notes

- Query scans a narrow time window (2h around alert time) for both tables - very fast
- CorrelationId inner join ensures only matching records are returned
- Expected result: 1 row (single risk event matched to its sign-in)
- If the join returns 0 rows, the risk event may have been an offline detection where the CorrelationId does not match. In that case, try matching on UserPrincipalName + time proximity instead

### Tuning Guidance

- **lookbackWindow**: Default 2h. Increase to 6h if the risk event was an offline detection (DetectionTimingType == "offline"), as the TimeGenerated may lag significantly behind the actual sign-in
- **If no CorrelationId match**: Fall back to joining on UserPrincipalName + IPAddress within a 30-minute window
- **Anonymous IP note**: LocationCity is frequently empty for anonymous IPs because Tor exit nodes and VPN endpoints often lack precise geolocation data

### Datatable Test Query

```kql
// ============================================================
// TEST: Query 1 - Extract Risk Event and Sign-In Details
// Synthetic data: 5 malicious + 10 benign risk events / sign-ins
// ============================================================
let testRiskEvents = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    RiskEventType: string,
    RiskLevel: string,
    RiskState: string,
    DetectionTimingType: string,
    IpAddress: string,
    Location: dynamic,
    CorrelationId: string,
    Id: string
) [
    // MALICIOUS 1: anonymous IP sign-in from Tor exit node (target - should match)
    datetime(2026-02-22T10:15:00Z), "user@contoso.com", "anonymizedIPAddress", "high", "atRisk", "realtime",
        "185.220.101.34", dynamic({"city":"","countryOrRegion":"DE"}),
        "corr-001", "risk-001",
    // MALICIOUS 2: same user, different anonymous IP, offline detection
    datetime(2026-02-22T04:00:00Z), "user@contoso.com", "anonymizedIPAddress", "medium", "atRisk", "offline",
        "104.244.76.13", dynamic({"city":"","countryOrRegion":"LU"}),
        "corr-010", "risk-010",
    // MALICIOUS 3: unfamiliar features for same user (different risk type - should NOT match)
    datetime(2026-02-22T10:00:00Z), "user@contoso.com", "unfamiliarFeatures", "medium", "atRisk", "realtime",
        "185.220.101.34", dynamic({"city":"","countryOrRegion":"DE"}),
        "corr-003", "risk-003",
    // MALICIOUS 4: same anonymous IP targeting different user (spray indicator)
    datetime(2026-02-22T10:17:00Z), "victim2@contoso.com", "anonymizedIPAddress", "high", "atRisk", "realtime",
        "185.220.101.34", dynamic({"city":"","countryOrRegion":"DE"}),
        "corr-011", "risk-011",
    // MALICIOUS 5: impossible travel for different user
    datetime(2026-02-22T09:00:00Z), "victim3@contoso.com", "impossibleTravel", "medium", "atRisk", "realtime",
        "198.51.100.50", dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        "corr-012", "risk-012",
    // BENIGN 1: legitimate VPN user (different user - should NOT match target)
    datetime(2026-02-22T08:00:00Z), "vpnuser@contoso.com", "anonymizedIPAddress", "low", "dismissed", "offline",
        "45.33.32.156", dynamic({"city":"","countryOrRegion":"US"}),
        "corr-002", "risk-002",
    // BENIGN 2: different user, normal sign-in
    datetime(2026-02-22T10:20:00Z), "other@contoso.com", "unfamiliarFeatures", "low", "atRisk", "realtime",
        "10.0.0.1", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        "corr-004", "risk-004",
    // BENIGN 3: ISP rotation triggered alert for different user
    datetime(2026-02-22T07:00:00Z), "john.doe@contoso.com", "unfamiliarFeatures", "low", "dismissed", "offline",
        "85.100.50.30", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        "corr-005", "risk-005",
    // BENIGN 4: new device triggered alert for different user
    datetime(2026-02-22T06:30:00Z), "jane.smith@contoso.com", "unfamiliarFeatures", "low", "dismissed", "offline",
        "10.1.1.100", dynamic({"city":"Ankara","countryOrRegion":"TR"}),
        "corr-006", "risk-006",
    // BENIGN 5: contractor VPN
    datetime(2026-02-22T09:00:00Z), "contractor@contoso.com", "anonymizedIPAddress", "low", "dismissed", "offline",
        "172.16.0.1", dynamic({"city":"London","countryOrRegion":"GB"}),
        "corr-007", "risk-007",
    // BENIGN 6: seasonal worker
    datetime(2026-02-21T09:00:00Z), "seasonal@contoso.com", "unfamiliarFeatures", "low", "dismissed", "offline",
        "85.100.50.40", dynamic({"city":"Izmir","countryOrRegion":"TR"}),
        "corr-008", "risk-008",
    // BENIGN 7: browser update triggered alert
    datetime(2026-02-22T05:45:00Z), "dev.user@contoso.com", "unfamiliarFeatures", "low", "dismissed", "offline",
        "10.1.1.50", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        "corr-009", "risk-009",
    // BENIGN 8: empty location edge case
    datetime(2026-02-22T11:00:00Z), "svc.account@contoso.com", "unfamiliarFeatures", "low", "dismissed", "offline",
        "10.1.1.200", dynamic(null),
        "corr-013", "risk-013",
    // BENIGN 9: mobile user on cellular
    datetime(2026-02-22T12:00:00Z), "mobile.user@contoso.com", "unfamiliarFeatures", "low", "dismissed", "offline",
        "100.64.0.1", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        "corr-014", "risk-014",
    // BENIGN 10: outside lookback window (should NOT match)
    datetime(2026-02-21T02:00:00Z), "user@contoso.com", "anonymizedIPAddress", "low", "dismissed", "offline",
        "185.220.101.34", dynamic({"city":"","countryOrRegion":"DE"}),
        "corr-015", "risk-015"
];
let testSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    Location: dynamic,
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
    // MALICIOUS 1: Tor Browser sign-in, no MFA (target - should match)
    datetime(2026-02-22T10:14:50Z), "user@contoso.com", "185.220.101.34",
        dynamic({"city":"","countryOrRegion":"DE"}),
        dynamic({"operatingSystem":"Windows 10","browser":"Tor Browser 13.0","isCompliant":"false","isManaged":"false","trustType":""}),
        "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-001", "sess-001",
    // MALICIOUS 2: different anonymous IP, VPN service
    datetime(2026-02-22T03:59:00Z), "user@contoso.com", "104.244.76.13",
        dynamic({"city":"","countryOrRegion":"LU"}),
        dynamic({"operatingSystem":"Linux","browser":"Firefox 115.0","isCompliant":"false","isManaged":"false","trustType":""}),
        "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0", "Azure Portal", "Windows Azure Service Management API", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-010", "sess-010",
    // MALICIOUS 3: unfamiliar features sign-in (same IP)
    datetime(2026-02-22T09:58:00Z), "user@contoso.com", "185.220.101.34",
        dynamic({"city":"","countryOrRegion":"DE"}),
        dynamic({"operatingSystem":"Windows 10","browser":"Tor Browser 13.0","isCompliant":"false","isManaged":"false","trustType":""}),
        "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-003", "sess-003",
    // MALICIOUS 4: spray victim sign-in
    datetime(2026-02-22T10:16:55Z), "victim2@contoso.com", "185.220.101.34",
        dynamic({"city":"","countryOrRegion":"DE"}),
        dynamic({"operatingSystem":"Windows 10","browser":"Tor Browser 13.0","isCompliant":"false","isManaged":"false","trustType":""}),
        "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-011", "sess-011",
    // MALICIOUS 5: impossible travel sign-in
    datetime(2026-02-22T08:59:00Z), "victim3@contoso.com", "198.51.100.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Linux","browser":"curl/7.88","isCompliant":"false","isManaged":"false","trustType":""}),
        "curl/7.88.0", "Azure Portal", "Windows Azure Service Management API", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-012", "sess-012",
    // BENIGN 1: legitimate VPN user with MFA passed
    datetime(2026-02-22T07:59:00Z), "vpnuser@contoso.com", "45.33.32.156",
        dynamic({"city":"","countryOrRegion":"US"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Chrome 122.0","isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Chrome/122.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-002", "sess-002",
    // BENIGN 2: normal user, managed device
    datetime(2026-02-22T10:19:00Z), "other@contoso.com", "10.0.0.1",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Edge 122.0","isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Edg/122.0", "Microsoft Teams", "Microsoft Teams", "Mobile Apps and Desktop clients",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppOTP","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-004", "sess-004",
    // BENIGN 3: ISP rotation
    datetime(2026-02-22T06:59:00Z), "john.doe@contoso.com", "85.100.50.30",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Chrome 122.0","isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Chrome/122.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-005", "sess-005",
    // BENIGN 4: new device
    datetime(2026-02-22T06:29:00Z), "jane.smith@contoso.com", "10.1.1.100",
        dynamic({"city":"Ankara","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"macOS 14","browser":"Safari 17.0","isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Safari/17.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppOTP","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-006", "sess-006",
    // BENIGN 5: contractor VPN
    datetime(2026-02-22T08:59:00Z), "contractor@contoso.com", "172.16.0.1",
        dynamic({"city":"London","countryOrRegion":"GB"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Chrome 122.0","isCompliant":"false","isManaged":"false","trustType":"Workplace"}),
        "Mozilla/5.0 Chrome/122.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-007", "sess-007",
    // BENIGN 6: outside lookback window
    datetime(2026-02-21T01:59:00Z), "user@contoso.com", "185.220.101.34",
        dynamic({"city":"","countryOrRegion":"DE"}),
        dynamic({"operatingSystem":"Windows 10","browser":"Tor Browser 13.0","isCompliant":"false","isManaged":"false","trustType":""}),
        "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-015", "sess-015"
];
// --- Test execution: should return 1 row for user@contoso.com anonymizedIPAddress ---
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-22T10:15:00Z);
let alertIP = "185.220.101.34";
let lookbackWindow = 2h;
let riskEvent = testRiskEvents
    | where TimeGenerated between ((alertTime - lookbackWindow) .. (alertTime + lookbackWindow))
    | where UserPrincipalName == targetUser
    | where RiskEventType == "anonymizedIPAddress"
    | where IpAddress == alertIP
    | project
        RiskTimeGenerated = TimeGenerated,
        UserPrincipalName,
        RiskEventType,
        RiskLevel,
        RiskState,
        DetectionTimingType,
        RiskIpAddress = IpAddress,
        RiskLocation = Location,
        CorrelationId,
        Id;
let signinDetails = testSigninLogs
    | where TimeGenerated between ((alertTime - lookbackWindow) .. (alertTime + lookbackWindow))
    | where UserPrincipalName == targetUser
    | project
        SigninTimeGenerated = TimeGenerated,
        UserPrincipalName,
        IPAddress,
        Location,
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
        MfaAuthDetail = iff(isnotempty(MfaDetail), tostring(MfaDetail.authDetail), ""),
        ConditionalAccessStatus,
        ResultType,
        ResultDescription = iff(ResultType == "0", "Success", ResultType),
        CorrelationId,
        SessionId;
riskEvent
| join kind=inner signinDetails on CorrelationId, UserPrincipalName
| project
    RiskTimeGenerated,
    DetectionTimingType,
    RiskLevel,
    RiskState,
    RiskEventType,
    UserPrincipalName,
    IPAddress,
    LocationCity = tostring(Location.city),
    LocationCountry = tostring(Location.countryOrRegion),
    DeviceOS,
    DeviceBrowser,
    DeviceIsCompliant,
    DeviceIsManaged,
    DeviceTrustType,
    UserAgent,
    AppDisplayName,
    ResourceDisplayName,
    ClientAppUsed,
    AuthenticationRequirement,
    MfaAuthMethod,
    MfaAuthDetail,
    ConditionalAccessStatus,
    ResultType,
    ResultDescription,
    CorrelationId,
    SessionId,
    SigninTimeGenerated
| order by RiskTimeGenerated desc
// Expected: 1 row - user@contoso.com, high risk, realtime, anonymizedIPAddress,
//           DE country, empty city, Tor Browser 13.0, no MFA, single factor, notApplied CA
```

---

## Query 2: Anonymous IP Classification (Tor/VPN/Proxy)

**Purpose:** Determine the type of anonymous IP used. Tor exit nodes, commercial VPNs, and open proxies have different risk profiles. Tor exit nodes are the highest risk indicator. Use UserAgent fingerprinting, ASN data from TI feeds, and known Tor exit node lists to classify.

**Tables:** SigninLogs, ThreatIntelligenceIndicator

**Investigation Step:** Step 2

### Production Query

```kql
// ============================================================
// Query 2: Anonymous IP Classification (Tor/VPN/Proxy)
// Purpose: Classify the anonymous IP as Tor exit node, VPN, or
//          open proxy using UserAgent, TI feeds, and sign-in
//          metadata patterns
// Tables: SigninLogs, ThreatIntelligenceIndicator
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-22T10:15:00Z);
let alertIP = "185.220.101.34";
let lookbackWindow = 2h;
// --- Part 1: Get the sign-in with full UserAgent context ---
let signinContext = SigninLogs
    | where TimeGenerated between ((alertTime - lookbackWindow) .. (alertTime + lookbackWindow))
    | where UserPrincipalName == targetUser
    | where IPAddress == alertIP
    | where ResultType == "0"
    | summarize arg_max(TimeGenerated, *) by IPAddress
    | project
        TimeGenerated,
        UserPrincipalName,
        IPAddress,
        UserAgent,
        DeviceBrowser = tostring(DeviceDetail.browser),
        DeviceOS = tostring(DeviceDetail.operatingSystem),
        LocationCity = tostring(Location.city),
        LocationCountry = tostring(Location.countryOrRegion),
        // Tor Browser has a distinctive UA pattern: Firefox ESR with specific rv: version
        // and Windows NT 10.0 regardless of actual OS (Tor Browser spoofs this)
        IsTorBrowserUA = iff(
            UserAgent has "rv:128.0" and UserAgent has "Gecko/20100101"
            and not(UserAgent has "Chrome") and not(UserAgent has "Edg")
            and not(UserAgent has "Safari/"),
            true, false
        ),
        // Check for known VPN client UserAgents
        IsVPNClientUA = iff(
            UserAgent has_any ("NordVPN", "ExpressVPN", "Surfshark", "ProtonVPN",
                "CyberGhost", "Private Internet Access", "Windscribe"),
            true, false
        );
// --- Part 2: Check TI feeds for Tor exit node classification ---
let tiMatch = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(90d)
    | where isnotempty(NetworkIP) or isnotempty(NetworkSourceIP)
    | where NetworkIP == alertIP or NetworkSourceIP == alertIP
    | where Active == true
    | summarize arg_max(TimeGenerated, *) by IndicatorId
    | project
        TITimeGenerated = TimeGenerated,
        ThreatType,
        Description,
        ConfidenceScore,
        Tags,
        SourceSystem,
        ExpirationDateTime,
        // Check for Tor-specific tags
        IsTorExitNode = iff(
            Tags has_any ("tor", "tor-exit", "tor-relay", "Tor", "TorExitNode")
            or Description has_any ("tor", "Tor exit", "Tor relay"),
            true, false
        ),
        IsAnonymizer = iff(
            Tags has_any ("anonymizer", "proxy", "vpn", "anonymous")
            or ThreatType has_any ("anonymizer", "proxy"),
            true, false
        );
// --- Part 3: Combine and classify ---
signinContext
| extend placeholder = 1
| join kind=leftouter (tiMatch | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1
| extend
    // Final classification logic
    AnonymousIPType = case(
        IsTorBrowserUA == true and IsTorExitNode == true,
            "CONFIRMED TOR - Browser UA + TI match",
        IsTorExitNode == true,
            "LIKELY TOR - TI feed match (exit node)",
        IsTorBrowserUA == true,
            "LIKELY TOR - Browser UA fingerprint match",
        IsVPNClientUA == true,
            "COMMERCIAL VPN - Known VPN client detected",
        IsAnonymizer == true,
            "ANONYMIZER/PROXY - TI feed match",
        LocationCity == "" and LocationCountry != "",
            "SUSPECTED ANONYMOUS - Empty city with country (common for VPN/proxy)",
        "UNKNOWN ANONYMOUS TYPE - Manual ASN investigation needed"
    ),
    RiskAssessment = case(
        IsTorBrowserUA == true or IsTorExitNode == true,
            "HIGH - Tor usage is rarely legitimate in enterprise environments",
        IsVPNClientUA == true,
            "MEDIUM - Check if user is authorized for VPN usage",
        IsAnonymizer == true,
            "MEDIUM-HIGH - Known anonymizer/proxy service",
        "MEDIUM - Anonymous IP type unknown, requires manual ASN lookup"
    )
| project
    UserPrincipalName,
    IPAddress,
    UserAgent,
    DeviceBrowser,
    DeviceOS,
    LocationCity,
    LocationCountry,
    // Classification results
    IsTorBrowserUA,
    IsTorExitNode,
    IsVPNClientUA,
    IsAnonymizer,
    AnonymousIPType,
    RiskAssessment,
    // TI context
    ThreatType,
    Description,
    ConfidenceScore,
    Tags,
    SourceSystem
```

### Expected Output Columns

| Column | Type | Description |
|---|---|---|
| UserPrincipalName | string | Target user |
| IPAddress | string | The anonymous IP address |
| UserAgent | string | Full user agent string for manual inspection |
| DeviceBrowser | string | Parsed browser name |
| DeviceOS | string | Parsed operating system |
| LocationCity | string | City (often empty for anonymous IPs) |
| LocationCountry | string | Country of the exit node |
| IsTorBrowserUA | bool | True if UA matches Tor Browser fingerprint |
| IsTorExitNode | bool | True if TI feeds flag this as Tor exit node |
| IsVPNClientUA | bool | True if UA matches known VPN client |
| IsAnonymizer | bool | True if TI feeds flag as anonymizer/proxy |
| AnonymousIPType | string | Final classification |
| RiskAssessment | string | Risk level with context |
| ThreatType | string | TI feed threat type |
| ConfidenceScore | int | TI confidence score |

### Performance Notes

- SigninLogs scan is narrow (2h window + user + IP filter) - very fast
- TI lookup uses `summarize arg_max` to get latest indicator per ID - efficient deduplication
- Left outer join ensures results are returned even when no TI match exists
- Expected result: 1 row with classification

### Tuning Guidance

- **Tor Browser UA pattern**: Tor Browser uses Firefox ESR with specific `rv:` versions. Update the `rv:128.0` check as Tor Browser updates its ESR base. As of 2026, Tor Browser 13.x uses Firefox ESR 128
- **VPN client list**: Add organization-approved VPN clients to a whitelist and exclude them from the `IsVPNClientUA` check
- **TI feed coverage**: If your TI feeds do not include Tor exit node lists, consider importing the Tor Project's public exit list via a Logic App connector to the ThreatIntelligenceIndicator table

---

## Query 3: Baseline Comparison - Establish Normal Behavior Pattern

**Purpose:** Build a 30-day behavioral baseline for the user and compare the flagged sign-in against it. This is the MANDATORY baseline step - you cannot determine anomaly without knowing what is normal. For anonymous IP alerts, special attention is paid to whether the user has ANY history of anonymous IP usage.

**Tables:** SigninLogs

**Investigation Step:** Step 3 (MANDATORY)

### Production Query

```kql
// ============================================================
// Query 3: Sign-In Baseline (30-day) - MANDATORY
// Purpose: Calculate what "normal" looks like for this user's
//          sign-ins over the past 30 days. For anonymous IP
//          alerts, specifically check if the user has EVER used
//          anonymous IPs, VPNs, or Tor before
// Table: SigninLogs
// MANDATORY - Do not skip this query
// Expected runtime: 5-10 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-22T10:15:00Z);
let alertIP = "185.220.101.34";
let baselinePeriod = 30d;
// Baseline window: from 30d ago to 1d ago (exclude recent day to avoid contamination)
let baselineStart = alertTime - baselinePeriod;
let baselineEnd = alertTime - 1d;
// --- Part 1: Calculate daily aggregates over baseline period ---
let dailyBaseline = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | summarize
        DailySignins = count(),
        DistinctIPs = dcount(IPAddress),
        DistinctCountries = dcount(tostring(Location.countryOrRegion)),
        DistinctCities = dcount(tostring(Location.city)),
        DistinctApps = dcount(AppDisplayName),
        DistinctDevices = dcount(tostring(DeviceDetail.operatingSystem)),
        DistinctBrowsers = dcount(tostring(DeviceDetail.browser))
        by bin(TimeGenerated, 1d);
// --- Part 2: Calculate statistical baseline from daily aggregates ---
let baselineStats = dailyBaseline
    | summarize
        BaselineDays = count(),
        AvgDailySignins = avg(DailySignins),
        StdevDailySignins = stdev(DailySignins),
        MaxDailySignins = max(DailySignins),
        AvgDistinctIPs = avg(DistinctIPs),
        MaxDistinctIPs = max(DistinctIPs),
        AvgDistinctCountries = avg(DistinctCountries),
        MaxDistinctCountries = max(DistinctCountries);
// --- Part 3: Collect known values from baseline ---
let knownIPs = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | distinct IPAddress;
let knownCountries = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | distinct tostring(Location.countryOrRegion);
let knownCities = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | distinct tostring(Location.city);
let knownApps = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | distinct AppDisplayName;
let knownBrowsers = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | distinct tostring(DeviceDetail.browser);
// --- Part 4: Check for prior anonymous IP usage (critical for this alert type) ---
let priorAnonymousIPUsage = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | where tostring(Location.city) == ""
    | summarize
        AnonymousIPSignins = count(),
        AnonymousIPs = make_set(IPAddress, 20),
        AnonymousCountries = make_set(tostring(Location.countryOrRegion), 10);
// --- Part 5: Analyze typical sign-in hours ---
let typicalHours = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | extend HourOfDay = hourofday(TimeGenerated)
    | summarize SigninsPerHour = count() by HourOfDay
    | order by HourOfDay asc;
// --- Part 6: Get the current sign-in details and compare ---
let currentSignin = SigninLogs
    | where TimeGenerated between ((alertTime - 2h) .. (alertTime + 1h))
    | where UserPrincipalName == targetUser
    | where IPAddress == alertIP
    | summarize arg_max(TimeGenerated, *) by IPAddress
    | extend
        CurrentIP = IPAddress,
        CurrentCountry = tostring(Location.countryOrRegion),
        CurrentCity = tostring(Location.city),
        CurrentApp = AppDisplayName,
        CurrentBrowser = tostring(DeviceDetail.browser),
        CurrentHour = hourofday(TimeGenerated);
// --- Part 7: Produce the comparison output ---
currentSignin
| extend
    IsIPNew = iff(CurrentIP in (knownIPs), "KNOWN", "NEW - NEVER SEEN IN 30 DAYS"),
    IsCountryNew = iff(CurrentCountry in (knownCountries), "KNOWN", "NEW - NEVER SEEN IN 30 DAYS"),
    IsCityNew = iff(CurrentCity in (knownCities), "KNOWN", "NEW - NEVER SEEN IN 30 DAYS"),
    IsAppNew = iff(CurrentApp in (knownApps), "KNOWN", "NEW - NEVER SEEN IN 30 DAYS"),
    IsBrowserNew = iff(CurrentBrowser in (knownBrowsers), "KNOWN", "NEW - NEVER SEEN IN 30 DAYS")
// Cross-join with baseline stats
| extend placeholder = 1
| join kind=inner (baselineStats | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1
// Cross-join with prior anonymous IP usage
| extend placeholder = 1
| join kind=inner (priorAnonymousIPUsage | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1
| extend
    NewPropertyCount = toint(IsIPNew == "NEW - NEVER SEEN IN 30 DAYS")
        + toint(IsCountryNew == "NEW - NEVER SEEN IN 30 DAYS")
        + toint(IsCityNew == "NEW - NEVER SEEN IN 30 DAYS")
        + toint(IsAppNew == "NEW - NEVER SEEN IN 30 DAYS")
        + toint(IsBrowserNew == "NEW - NEVER SEEN IN 30 DAYS"),
    // Anonymous-IP-specific anomaly assessment
    AnomalyAssessment = case(
        AnonymousIPSignins == 0 and IsBrowserNew == "NEW - NEVER SEEN IN 30 DAYS",
            "HIGH ANOMALY - User has NEVER used anonymous IPs + new browser",
        AnonymousIPSignins == 0,
            "HIGH ANOMALY - User has NEVER used anonymous IPs in 30 days",
        CurrentIP !in (AnonymousIPs) and IsBrowserNew == "NEW - NEVER SEEN IN 30 DAYS",
            "MEDIUM ANOMALY - New anonymous IP + new browser (user has used other anonymous IPs before)",
        CurrentIP in (AnonymousIPs),
            "LOW ANOMALY - User has used this SAME anonymous IP before (possible legitimate VPN)",
        AnonymousIPSignins > 0,
            "LOW-MEDIUM ANOMALY - User has used different anonymous IPs before",
        "REVIEW REQUIRED"
    ),
    HasPriorAnonymousUsage = iff(AnonymousIPSignins > 0,
        strcat("YES - ", AnonymousIPSignins, " sign-ins from anonymous IPs in baseline"),
        "NO - First anonymous IP usage for this user")
| project
    UserPrincipalName,
    // Current sign-in properties
    CurrentIP,
    CurrentCountry,
    CurrentCity,
    CurrentApp,
    CurrentBrowser,
    CurrentHour,
    // Baseline comparison
    IsIPNew,
    IsCountryNew,
    IsCityNew,
    IsAppNew,
    IsBrowserNew,
    NewPropertyCount,
    // Anonymous IP history (unique to RB-0004)
    HasPriorAnonymousUsage,
    AnonymousIPSignins,
    AnonymousIPs,
    AnonymousCountries,
    // Baseline statistics
    BaselineDays,
    AvgDailySignins,
    StdevDailySignins,
    MaxDailySignins,
    AvgDistinctIPs,
    MaxDistinctIPs,
    // Final assessment
    AnomalyAssessment
```

### Expected Output Columns

| Column | Type | Description |
|---|---|---|
| UserPrincipalName | string | Target user |
| CurrentIP / CurrentCountry / CurrentCity | string | Current sign-in properties |
| CurrentApp / CurrentBrowser | string | Current sign-in properties |
| CurrentHour | int | Hour of day of current sign-in |
| IsIPNew / IsCountryNew / IsCityNew | string | "KNOWN" or "NEW - NEVER SEEN IN 30 DAYS" |
| IsAppNew / IsBrowserNew | string | "KNOWN" or "NEW - NEVER SEEN IN 30 DAYS" |
| NewPropertyCount | int | Count of new properties (0-5) |
| HasPriorAnonymousUsage | string | Whether user has EVER used anonymous IPs |
| AnonymousIPSignins | long | Count of prior anonymous IP sign-ins |
| AnonymousIPs | dynamic | Set of previously used anonymous IPs |
| AnonymousCountries | dynamic | Countries of prior anonymous IPs |
| BaselineDays | long | Number of days in baseline |
| AvgDailySignins / StdevDailySignins | double | Statistical baseline |
| AnomalyAssessment | string | Overall classification |

### Performance Notes

- Query scans 30 days of SigninLogs for a single user - moderate volume
- The `distinct` subqueries (knownIPs, knownCountries, etc.) use materialized temp tables - efficient
- The prior anonymous IP check (Part 4) uses empty city as a heuristic for anonymous IPs - this is not 100% accurate but covers most cases
- If the user is a service account with thousands of daily sign-ins, consider reducing baselinePeriod to 14d

### Tuning Guidance

- **baselinePeriod**: Default 30d. Use 14d for high-volume accounts. Use 60d for infrequent users
- **Anonymous IP heuristic**: Empty city (`tostring(Location.city) == ""`) is used as a proxy for anonymous IPs. Some legitimate scenarios (mobile cellular, satellite internet) may also have empty city. Cross-reference with Query 2's TI classification
- **AnomalyAssessment thresholds**: If the organization has users who legitimately use VPNs (remote workers, privacy-conscious employees), adjust the "HIGH ANOMALY" threshold to account for known VPN IPs

---

## Query 4: Sign-In Session Analysis from Anonymous IP

**Purpose:** Analyze all sign-in activity from the anonymous IP during the alert window. Check for session patterns, multiple applications accessed, failed attempts before success (credential testing), and session duration anomalies.

**Tables:** SigninLogs

**Investigation Step:** Step 4

### Production Query

```kql
// ============================================================
// Query 4: Sign-In Session Analysis from Anonymous IP
// Purpose: Analyze all sign-in activity from the anonymous IP
//          including failed attempts, multi-app access, and
//          session patterns that indicate credential testing
//          or account takeover
// Table: SigninLogs
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-22T10:15:00Z);
let alertIP = "185.220.101.34";
let sessionWindow = 4h;
// --- All sign-ins from this IP for the target user (success + failure) ---
SigninLogs
| where TimeGenerated between ((alertTime - sessionWindow) .. (alertTime + sessionWindow))
| where UserPrincipalName == targetUser
| where IPAddress == alertIP
| extend
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    DeviceBrowser = tostring(DeviceDetail.browser),
    LocationCity = tostring(Location.city),
    LocationCountry = tostring(Location.countryOrRegion),
    MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "No MFA performed"),
    // Classify the sign-in result
    SignInResult = case(
        ResultType == "0", "Success",
        ResultType == "50126", "Invalid password",
        ResultType == "50074", "MFA required - user did not complete",
        ResultType == "50076", "MFA required - strong auth required",
        ResultType == "53003", "Blocked by Conditional Access",
        ResultType == "530032", "Blocked - security defaults",
        ResultType == "50053", "Account locked",
        ResultType == "50057", "Account disabled",
        ResultType == "50055", "Password expired",
        strcat("Error: ", ResultType)
    )
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AppDisplayName,
    ResourceDisplayName,
    ClientAppUsed,
    DeviceOS,
    DeviceBrowser,
    LocationCountry,
    AuthenticationRequirement,
    MfaAuthMethod,
    ConditionalAccessStatus,
    ResultType,
    SignInResult,
    CorrelationId,
    SessionId
| order by TimeGenerated asc
| extend
    // Detect credential testing pattern: failed attempts followed by success
    PrevResult = prev(ResultType),
    PrevTime = prev(TimeGenerated),
    TimeSincePrevSignin = datetime_diff("second", TimeGenerated, prev(TimeGenerated))
| extend
    SessionPattern = case(
        ResultType == "0" and PrevResult != "0" and isnotempty(PrevResult),
            "SUSPICIOUS - Success after failure (possible credential testing)",
        ResultType != "0" and TimeSincePrevSignin < 10 and isnotempty(TimeSincePrevSignin),
            "SUSPICIOUS - Rapid failed attempts (<10s interval)",
        ResultType == "0" and isempty(PrevResult),
            "First sign-in in session",
        ResultType == "0",
            "Continued successful session",
        "Failed attempt"
    )
```

### Expected Output Columns

| Column | Type | Description |
|---|---|---|
| TimeGenerated | datetime | Sign-in timestamp |
| AppDisplayName | string | Target application |
| SignInResult | string | Human-readable result |
| ResultType | string | Raw result code (string) |
| SessionId | string | Session identifier |
| SessionPattern | string | Pattern analysis (credential testing detection) |
| TimeSincePrevSignin | long | Seconds since previous sign-in from same IP |

### Performance Notes

- Scans a narrow window (4h) filtered by user + IP - very fast
- Uses `prev()` window function to detect sequential patterns - requires `order by TimeGenerated asc` first
- Expected result: 1-10 rows depending on session activity

### Tuning Guidance

- **sessionWindow**: Default 4h. Expand to 24h if you want to see the full scope of activity from this IP
- **ResultType mapping**: Add organization-specific error codes as needed. The common codes listed cover 90% of scenarios
- **Credential testing threshold**: The `TimeSincePrevSignin < 10` check flags rapid-fire attempts. Adjust for environments with legitimate rapid auth flows

---

## Query 5: Non-Interactive Sign-Ins from Anonymous IP

**Purpose:** Check for non-interactive (token-based) sign-ins from the anonymous IP. If tokens were stolen or a session was hijacked, non-interactive sign-ins will continue from the anonymous IP even after the interactive sign-in session ends.

**Tables:** AADNonInteractiveUserSignInLogs

**Investigation Step:** Step 5

### Production Query

```kql
// ============================================================
// Query 5: Non-Interactive Sign-Ins from Anonymous IP
// Purpose: Detect token replay or session hijacking by checking
//          for non-interactive sign-ins from the anonymous IP.
//          These indicate ongoing access via refresh tokens
// Table: AADNonInteractiveUserSignInLogs
// Note: This table is HIGH VOLUME - always filter by user + IP
//       (Hasan's recommendation)
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-22T10:15:00Z);
let alertIP = "185.220.101.34";
// Check from alert time forward to detect ongoing token usage
let postAlertWindow = 24h;
AADNonInteractiveUserSignInLogs
| where TimeGenerated between (alertTime .. (alertTime + postAlertWindow))
| where UserPrincipalName == targetUser
| where IPAddress == alertIP
// ResultType is a STRING in this table too (Hasan's gotcha)
| extend
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    DeviceBrowser = tostring(DeviceDetail.browser),
    LocationCountry = tostring(Location.countryOrRegion),
    SignInResult = iff(ResultType == "0", "Success", strcat("Error: ", ResultType))
| summarize
    TokenRefreshCount = count(),
    FirstTokenRefresh = min(TimeGenerated),
    LastTokenRefresh = max(TimeGenerated),
    DistinctApps = make_set(AppDisplayName, 20),
    DistinctResources = make_set(ResourceDisplayName, 20),
    ResultCodes = make_set(ResultType, 10)
    by UserPrincipalName, IPAddress, DeviceOS, DeviceBrowser, LocationCountry
| extend
    SessionDurationMinutes = datetime_diff("minute", LastTokenRefresh, FirstTokenRefresh),
    // Flag long-running token sessions from anonymous IPs
    TokenPersistenceRisk = case(
        TokenRefreshCount > 50 and SessionDurationMinutes > 120,
            "HIGH - Sustained token usage (>50 refreshes, >2hr session) from anonymous IP",
        TokenRefreshCount > 20,
            "MEDIUM - Elevated token refresh count from anonymous IP",
        TokenRefreshCount > 0,
            "LOW - Token activity detected from anonymous IP",
        "NONE - No non-interactive sign-ins from this IP"
    )
| project
    UserPrincipalName,
    IPAddress,
    DeviceOS,
    DeviceBrowser,
    LocationCountry,
    TokenRefreshCount,
    FirstTokenRefresh,
    LastTokenRefresh,
    SessionDurationMinutes,
    DistinctApps,
    DistinctResources,
    ResultCodes,
    TokenPersistenceRisk
| order by TokenRefreshCount desc
```

### Expected Output Columns

| Column | Type | Description |
|---|---|---|
| UserPrincipalName | string | Target user |
| IPAddress | string | Anonymous IP address |
| TokenRefreshCount | long | Number of non-interactive sign-ins |
| FirstTokenRefresh | datetime | First token refresh timestamp |
| LastTokenRefresh | datetime | Last token refresh timestamp |
| SessionDurationMinutes | long | Duration of token session |
| DistinctApps | dynamic | Applications accessed via tokens |
| DistinctResources | dynamic | Resources accessed via tokens |
| TokenPersistenceRisk | string | Risk assessment |

### Performance Notes

- AADNonInteractiveUserSignInLogs is high volume - always filter by UserPrincipalName AND IPAddress
- The summarize pattern aggregates potentially thousands of token refreshes into a single summary row
- Expected result: 0-1 rows (0 if no token activity, 1 summarized row if present)

### Tuning Guidance

- **postAlertWindow**: Default 24h. Extend to 48-72h if investigating delayed response scenarios
- **TokenRefreshCount thresholds**: Adjust based on organizational norms. Some legitimate apps (Teams, Outlook) generate high token refresh volumes
- **If high volume**: Add `| where ResultType == "0"` to focus only on successful token refreshes

---

## Query 6A: Directory Changes After Anonymous Sign-In

**Purpose:** Check for persistence mechanisms created via directory operations (MFA changes, app consents, role assignments) after the anonymous IP sign-in. Attackers using anonymous IPs often immediately establish persistence before the IP is blocked.

**Tables:** AuditLogs

**Investigation Step:** Step 6

### Production Query

```kql
// ============================================================
// Query 6A: Directory Changes After Anonymous Sign-In
// Purpose: Check for persistence mechanisms created via
//          directory operations after the anonymous IP sign-in
// Table: AuditLogs
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-22T10:15:00Z);
// Use 4-hour window per Hasan's recommendation (accounts for latency)
let postSignInWindow = 4h;
AuditLogs
| where TimeGenerated between (alertTime .. (alertTime + postSignInWindow))
// Filter for high-risk operations
| where OperationName in (
    // MFA / authentication persistence
    "User registered security info",
    "User deleted security info",
    "Admin registered security info",
    "Register security info",
    "Update StsRefreshTokenValidFrom",
    // Application consent (OAuth abuse)
    "Consent to application",
    "Add app role assignment to service principal",
    "Add delegated permission grant",
    "Add owner to application",
    "Add app role assignment grant to user",
    // Account manipulation
    "Update user",
    "Reset password (by admin)",
    "Reset user password",
    "Change user password",
    // Device registration
    "Register device",
    "Add registered owner to device",
    // Role escalation
    "Add member to role",
    "Add eligible member to role"
)
| mv-expand TargetResource = TargetResources
// Check if the target user initiated OR is the target of the operation
| where tostring(InitiatedBy.user.userPrincipalName) == targetUser
    or tostring(TargetResource.userPrincipalName) == targetUser
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
    MinutesAfterAlert = datetime_diff("minute", TimeGenerated, alertTime),
    // Severity classification for post-sign-in activity
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

### Performance Notes

- Scans 4 hours of AuditLogs filtered by specific OperationName values - very fast
- If the alert is very recent (<1 hour), some AuditLogs entries may still be ingesting. Re-run after 2 hours

### Tuning Guidance

- **postSignInWindow**: Default 4h. For fast triage use 2h. For thorough investigation expand to 24h
- **OperationName list**: This covers the most common persistence operations. Add organization-specific operations as needed

---

## Query 6B: Email and File Activity After Anonymous Sign-In

**Purpose:** Check for inbox rule creation, email forwarding, bulk email access, and file exfiltration patterns after the anonymous IP sign-in. Attackers using anonymous IPs often target email for BEC or data exfiltration.

**Tables:** OfficeActivity

**Investigation Step:** Step 6

### Production Query

```kql
// ============================================================
// Query 6B: Email and File Activity After Anonymous Sign-In
// Purpose: Check for inbox rule creation, email forwarding,
//          bulk email access, and file exfiltration patterns
// Table: OfficeActivity
// Note: OfficeActivity has up to 60 min ingestion latency.
//       If the alert is <1 hour old, results may be incomplete.
//       Re-run this query after 1-2 hours for full coverage.
// Expected runtime: 5-10 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-22T10:15:00Z);
let alertIP = "185.220.101.34";
// 4-hour window per Hasan's latency guidance
let postSignInWindow = 4h;
OfficeActivity
| where TimeGenerated between (alertTime .. (alertTime + postSignInWindow))
// UserId in OfficeActivity uses UPN format
| where UserId == targetUser
// IP normalization - OfficeActivity.ClientIP can include port numbers
// and IPv6-mapped formats like [::ffff:1.2.3.4]:port (Hasan's gotcha)
| extend CleanClientIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)
| project
    TimeGenerated,
    Operation,
    OfficeWorkload,
    UserId,
    CleanClientIP,
    RawClientIP = ClientIP,
    MinutesAfterAlert = datetime_diff("minute", TimeGenerated, alertTime),
    // Flag if activity came from the anonymous IP specifically
    FromAnonymousIP = iff(CleanClientIP == alertIP, "YES - FROM ANONYMOUS IP", "No - different IP"),
    // Classify operations by risk
    RiskCategory = case(
        // PERSISTENCE - Inbox rules
        Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule"),
            "CRITICAL - INBOX RULE",
        // PERSISTENCE - Email forwarding
        Operation in ("Set-Mailbox", "Set-TransportRule") and OfficeWorkload == "Exchange",
            "CRITICAL - MAILBOX FORWARDING",
        // PERSISTENCE - Delegate access
        Operation in ("Add-MailboxPermission", "Add-RecipientPermission"),
            "HIGH - DELEGATE ACCESS",
        // DATA ACCESS - Email
        Operation == "MailItemsAccessed",
            "MONITOR - EMAIL ACCESS",
        Operation == "Send",
            "MONITOR - EMAIL SENT",
        Operation in ("SearchQuery", "SearchStarted"),
            "MONITOR - EMAIL SEARCH",
        // DATA ACCESS - Files
        Operation in ("FileDownloaded", "FileSyncDownloadedFull"),
            "MONITOR - FILE DOWNLOAD",
        Operation in ("FileAccessed", "FileAccessedExtended"),
            "INFO - FILE ACCESS",
        Operation == "FileUploaded",
            "MONITOR - FILE UPLOAD",
        "INFO"
    ),
    Parameters
| order by TimeGenerated asc
```

### Expected Output Columns

| Column | Type | Description |
|---|---|---|
| TimeGenerated | datetime | Activity timestamp |
| Operation | string | What happened (New-InboxRule, FileDownloaded, etc.) |
| OfficeWorkload | string | Service (Exchange, SharePoint, OneDrive, Teams) |
| CleanClientIP | string | Normalized client IP |
| FromAnonymousIP | string | Whether this activity came from the anonymous IP |
| MinutesAfterAlert | long | Minutes after the alert |
| RiskCategory | string | Severity classification |

### Performance Notes

- Scans 4 hours of OfficeActivity for a single user - fast
- MailItemsAccessed can generate very high volume in E5 environments
- The `extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)` regex normalizes all ClientIP formats to plain IPv4

### Tuning Guidance

- **postSignInWindow**: Default 4h. For fast triage use 2h but note potential data gaps due to OfficeActivity ingestion latency
- **FromAnonymousIP filter**: Add `| where FromAnonymousIP == "YES - FROM ANONYMOUS IP"` to focus only on activity from the anonymous IP specifically

---

## Query 6C: Inbox Rule Deep Dive

**Purpose:** Extract detailed inbox rule parameters to determine if rules are malicious (forwarding to external addresses, deleting messages, hiding emails with financial keywords). This is the primary persistence mechanism in BEC attacks.

**Tables:** OfficeActivity

**Investigation Step:** Step 6

### Production Query

```kql
// ============================================================
// Query 6C: Inbox Rule Deep Dive
// Purpose: Extract inbox rule creation details - the #1
//          persistence mechanism in BEC attacks. Anonymous IP
//          sign-ins followed by inbox rule creation is a strong
//          indicator of compromise
// Table: OfficeActivity
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-22T10:15:00Z);
let postSignInWindow = 4h;
OfficeActivity
| where TimeGenerated between (alertTime .. (alertTime + postSignInWindow))
| where UserId == targetUser
| where Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule")
// Parse the Parameters column to extract rule details
| mv-expand Parameter = parse_json(Parameters)
| summarize
    RuleParameters = make_bag(pack(tostring(Parameter.Name), tostring(Parameter.Value)))
    by TimeGenerated, Operation, UserId, ClientIP
| extend
    RuleName = tostring(RuleParameters.Name),
    // These are the critical indicators of malicious inbox rules
    ForwardTo = tostring(RuleParameters.ForwardTo),
    ForwardAsAttachmentTo = tostring(RuleParameters.ForwardAsAttachmentTo),
    RedirectTo = tostring(RuleParameters.RedirectTo),
    DeleteMessage = tostring(RuleParameters.DeleteMessage),
    MarkAsRead = tostring(RuleParameters.MarkAsRead),
    MoveToFolder = tostring(RuleParameters.MoveToFolder),
    SubjectContainsWords = tostring(RuleParameters.SubjectContainsWords),
    FromAddressContainsWords = tostring(RuleParameters.FromAddressContainsWords)
| extend
    CleanClientIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP),
    // Flag malicious patterns
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
    CleanClientIP
```

### Expected Output Columns

| Column | Type | Description |
|---|---|---|
| TimeGenerated | datetime | When the rule was created/modified |
| Operation | string | New-InboxRule, Set-InboxRule, or Enable-InboxRule |
| RuleName | string | Name of the inbox rule |
| ForwardTo | string | External forwarding address (CRITICAL if present) |
| RedirectTo | string | Redirect address (CRITICAL if present) |
| DeleteMessage | string | "True" if rule deletes messages (hiding evidence) |
| MarkAsRead | string | "True" if rule marks as read (hiding evidence) |
| SubjectContainsWords | string | Keywords the rule filters on |
| IsMalicious | string | "LIKELY MALICIOUS" or "REVIEW REQUIRED" |
| CleanClientIP | string | Normalized source IP |

### Performance Notes

- Very fast query - narrow time window and specific Operation filter
- The `mv-expand` + `make_bag` pattern handles the variable parameter structure of inbox rules
- Expected result: 0 rows (no inbox rules) or 1-3 rows if rules were created

### Tuning Guidance

- **Financial keywords**: Add industry-specific keywords to the `has_any` check (e.g., "PO", "purchase order", "remittance", "ACH")
- **External domain check**: Consider adding a check for `ForwardTo` containing non-organizational domains

---

## Query 7A: IP Reputation (TI Feeds)

**Purpose:** Look up the anonymous IP address in Threat Intelligence feeds to determine if it is a known malicious IP, Tor exit node, or documented anonymizer. This provides external context beyond Microsoft's built-in detection.

**Tables:** ThreatIntelligenceIndicator

**Investigation Step:** Step 7

### Production Query

```kql
// ============================================================
// Query 7A: IP Reputation (TI Feeds)
// Purpose: Look up the anonymous IP in TI feeds for known
//          malicious activity, Tor exit node status, and
//          historical threat context
// Table: ThreatIntelligenceIndicator
// Expected runtime: <3 seconds
// Required: Optional (depends on TI feed availability)
// ============================================================
let alertIP = "185.220.101.34";
ThreatIntelligenceIndicator
| where TimeGenerated > ago(90d)
| where isnotempty(NetworkIP) or isnotempty(NetworkSourceIP)
| where NetworkIP == alertIP or NetworkSourceIP == alertIP
| where Active == true
| summarize arg_max(TimeGenerated, *) by IndicatorId
| project
    TimeGenerated,
    ThreatType,
    Description,
    ConfidenceScore,
    Tags,
    SourceSystem,
    ExpirationDateTime,
    NetworkIP,
    NetworkSourceIP,
    // Classify the IP based on TI context
    IPClassification = case(
        Tags has_any ("tor", "tor-exit", "TorExitNode", "Tor")
            or Description has_any ("Tor exit", "Tor relay", "tor node"),
            "TOR EXIT NODE",
        Tags has_any ("botnet", "c2", "command-and-control"),
            "BOTNET/C2 INFRASTRUCTURE",
        Tags has_any ("malware", "phishing", "exploit"),
            "KNOWN MALICIOUS",
        Tags has_any ("scanner", "scan", "reconnaissance"),
            "SCANNER/RECON",
        Tags has_any ("anonymizer", "proxy", "vpn"),
            "ANONYMIZER/PROXY",
        ThreatType has_any ("Malware", "Phishing", "BotNet"),
            strcat("THREAT: ", ThreatType),
        isnotempty(ThreatType),
            strcat("OTHER: ", ThreatType),
        "UNCATEGORIZED TI MATCH"
    ),
    RiskLevel = case(
        ConfidenceScore >= 80, "HIGH CONFIDENCE",
        ConfidenceScore >= 50, "MEDIUM CONFIDENCE",
        ConfidenceScore > 0, "LOW CONFIDENCE",
        "UNKNOWN CONFIDENCE"
    )
| order by ConfidenceScore desc
```

### Expected Output Columns

| Column | Type | Description |
|---|---|---|
| ThreatType | string | Type of threat from TI feed |
| Description | string | Description from TI feed |
| ConfidenceScore | int | Confidence level (0-100) |
| Tags | dynamic | Tags associated with the indicator |
| IPClassification | string | Derived classification |
| RiskLevel | string | Confidence-based risk level |

### Performance Notes

- Scans TI indicators from the last 90 days for a single IP - very fast
- Uses `summarize arg_max` to deduplicate indicators by IndicatorId
- Expected result: 0 rows (no TI match) or 1+ rows if IP is in TI feeds
- If 0 rows returned, it does not mean the IP is safe - TI coverage varies by feed

### Tuning Guidance

- **TI feed coverage**: Results depend entirely on which TI feeds are connected to Sentinel. Common feeds: Microsoft TI, AlienVault OTX, Abuse.ch, Tor exit list
- **Confidence threshold**: Filter with `| where ConfidenceScore >= 50` to reduce noise from low-confidence indicators

---

## Query 7B: Organizational IP Usage Check

**Purpose:** Determine if the anonymous IP has been used by other users in the organization. If multiple users sign in from the same anonymous IP, it could indicate either a shared corporate VPN exit point or a coordinated attack targeting multiple accounts.

**Tables:** SigninLogs

**Investigation Step:** Step 7

### Production Query

```kql
// ============================================================
// Query 7B: Organizational IP Usage Check
// Purpose: Check if other users in the organization have signed
//          in from the same anonymous IP. Multiple users from
//          the same anonymous IP = either shared VPN or spray attack
// Table: SigninLogs
// Expected runtime: 5-10 seconds
// ============================================================
let alertIP = "185.220.101.34";
let alertTime = datetime(2026-02-22T10:15:00Z);
let targetUser = "user@contoso.com";
// Check 30 days of organizational usage
let orgLookback = 30d;
SigninLogs
| where TimeGenerated between ((alertTime - orgLookback) .. alertTime)
| where IPAddress == alertIP
| summarize
    SignInCount = count(),
    SuccessCount = countif(ResultType == "0"),
    FailureCount = countif(ResultType != "0"),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    DistinctApps = make_set(AppDisplayName, 20),
    ResultCodes = make_set(ResultType, 10),
    DistinctBrowsers = make_set(tostring(DeviceDetail.browser), 10),
    DistinctOSes = make_set(tostring(DeviceDetail.operatingSystem), 10)
    by UserPrincipalName
| extend
    IsTargetUser = iff(UserPrincipalName == targetUser, "TARGET USER", "Other user"),
    DaysActive = datetime_diff("day", LastSeen, FirstSeen) + 1,
    SuccessRate = round(100.0 * SuccessCount / SignInCount, 1)
| order by SignInCount desc
| extend
    // Assess the organizational usage pattern
    UsagePattern = case(
        // Only the target user has used this IP
        IsTargetUser == "TARGET USER" and toscalar(
            SigninLogs
            | where TimeGenerated between ((alertTime - orgLookback) .. alertTime)
            | where IPAddress == alertIP
            | distinct UserPrincipalName
            | count
        ) == 1,
            "UNIQUE - Only the target user has used this IP in 30 days",
        // Multiple users, high failure rate = spray attack
        FailureCount > SuccessCount,
            "SUSPICIOUS - High failure rate suggests credential testing",
        // Single sign-in from this user
        SignInCount == 1,
            "ONE-TIME - Single sign-in from this IP",
        // Regular usage
        DaysActive > 7,
            "REGULAR - Used across multiple days (possible legitimate VPN)",
        "REVIEW - Intermittent usage"
    )
| project
    UserPrincipalName,
    IsTargetUser,
    SignInCount,
    SuccessCount,
    FailureCount,
    SuccessRate,
    FirstSeen,
    LastSeen,
    DaysActive,
    DistinctApps,
    DistinctBrowsers,
    DistinctOSes,
    ResultCodes,
    UsagePattern
```

### Expected Output Columns

| Column | Type | Description |
|---|---|---|
| UserPrincipalName | string | User who signed in from the IP |
| IsTargetUser | string | "TARGET USER" or "Other user" |
| SignInCount | long | Total sign-ins from this IP |
| SuccessCount | long | Successful sign-ins |
| FailureCount | long | Failed sign-ins |
| SuccessRate | double | Percentage of successful sign-ins |
| FirstSeen / LastSeen | datetime | IP usage date range |
| DaysActive | long | Number of days this IP was used |
| DistinctApps | dynamic | Applications accessed from this IP |
| DistinctBrowsers | dynamic | Browsers used from this IP |
| UsagePattern | string | Organizational usage assessment |

### Performance Notes

- Scans 30 days of SigninLogs filtered by a single IP - moderate volume
- The `toscalar` subquery inside `case` adds a small overhead but only runs once
- Expected result: 1 row if only the target user used this IP, multiple rows if shared
- If the IP is a Tor exit node, expect multiple users (Tor exit nodes are shared by many users globally)

### Tuning Guidance

- **orgLookback**: Default 30d. Reduce to 7d for faster triage, expand to 90d for comprehensive history
- **Multi-user from same anonymous IP**: If >5 distinct users have signed in from the same anonymous IP, this strongly indicates either a corporate VPN endpoint (benign) or a spray attack infrastructure (malicious). Cross-reference with Query 2 classification
- **Failure rate analysis**: A SuccessRate below 20% from multiple users strongly indicates credential testing/spray from this IP

---

## Key KQL Patterns Used

### RiskEventType filter for anonymous IP
```kql
// AADUserRiskEvents uses "anonymizedIPAddress" as the RiskEventType
// Note the camelCase spelling - not "anonymousIPAddress" or "AnonymizedIPAddress"
| where RiskEventType == "anonymizedIPAddress"
```

### IpAddress vs IPAddress field naming
```kql
// AADUserRiskEvents: IpAddress (capital A, lowercase p)
AADUserRiskEvents | project IpAddress

// SigninLogs: IPAddress (capital I, capital P)
SigninLogs | project IPAddress

// AADNonInteractiveUserSignInLogs: IPAddress (capital I, capital P)
AADNonInteractiveUserSignInLogs | project IPAddress
```

### ResultType as STRING comparison
```kql
// ResultType is a STRING in all sign-in tables, not an integer
// Always compare as string with quotes
| where ResultType == "0"     // Correct
// | where ResultType == 0    // WRONG - will not match
```

### Tor Browser UserAgent fingerprint detection
```kql
// Tor Browser is based on Firefox ESR with specific version patterns
// It spoofs Windows NT 10.0 regardless of actual OS
// Current Tor Browser 13.x uses Firefox ESR 128 (rv:128.0)
| extend IsTorBrowserUA = iff(
    UserAgent has "rv:128.0" and UserAgent has "Gecko/20100101"
    and not(UserAgent has "Chrome") and not(UserAgent has "Edg")
    and not(UserAgent has "Safari/"),
    true, false
)
```

### tostring() for dynamic field extraction
```kql
// DeviceDetail, Location, MfaDetail are dynamic columns
// Always use tostring() when projecting nested fields
| extend
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    DeviceBrowser = tostring(DeviceDetail.browser),
    LocationCity = tostring(Location.city),
    LocationCountry = tostring(Location.countryOrRegion)
```

### iff(isnotempty(...)) for MfaDetail null handling
```kql
// MfaDetail is null/empty when MFA was not performed
// Using tostring() on null returns "" - iff guards against this
MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "No MFA performed"),
MfaAuthDetail = iff(isnotempty(MfaDetail), tostring(MfaDetail.authDetail), "")
```

### extract() regex for OfficeActivity ClientIP normalization
```kql
// OfficeActivity ClientIP formats vary:
// "1.2.3.4"             - plain IPv4
// "1.2.3.4:12345"       - IPv4 with port
// "[::ffff:1.2.3.4]:80" - IPv6-mapped IPv4 with port
// This regex extracts just the IPv4 address from any format
| extend CleanClientIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)
```

### Anonymous IP detection heuristic (empty city)
```kql
// Anonymous IPs (Tor, VPN, proxy) typically have empty city in Location
// because exit nodes lack precise geolocation
// This is a heuristic - not 100% accurate (mobile/satellite may also be empty)
| where tostring(Location.city) == ""
```

## Optimization Notes

1. **Always filter by user + time first** - these are the most selective predicates
2. **IpAddress vs IPAddress** - AADUserRiskEvents uses `IpAddress` (capital A); SigninLogs and AADNonInteractiveUserSignInLogs use `IPAddress` (capital IP). Getting this wrong returns 0 rows with no error
3. **AADNonInteractiveUserSignInLogs is high volume** - always add both user AND IP filter when possible
4. **ResultType is a string** - compare with `"0"` not `0`. This applies to SigninLogs, AADNonInteractiveUserSignInLogs, and AADUserRiskEvents
5. **OfficeActivity ingestion latency** - up to 60 min. Re-run 2 hours after alert for completeness
6. **OfficeActivity ClientIP normalization** - always use `extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)` to handle port numbers and IPv6-mapped formats
7. **Tor Browser UA evolves** - update the `rv:128.0` pattern as Tor Browser releases new versions based on newer Firefox ESR
8. **Anonymous IP empty city heuristic** - use `tostring(Location.city) == ""` as a rough filter for anonymous IPs, but always cross-reference with TI feeds (Query 2/7A) for confirmation
9. **TI feed dependency** - Query 2 and 7A depend on TI feeds being configured in Sentinel. If no TI feeds are available, rely on UserAgent fingerprinting and organizational usage patterns
10. **Use `summarize arg_max()` instead of `take 1`** - for deterministic results when selecting a single record per group
