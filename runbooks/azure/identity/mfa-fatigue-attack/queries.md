# Query Reference - MFA Fatigue Attack (RB-0005)

> **Author:** Samet (KQL Engineer)
> **Reviewed by:** Hasan (Platform Architect), Alp (QA Lead)
> **Version:** 1.0
> **Date:** 2026-02-22

## Query Inventory

| # | Query | Step | Tables | Purpose | Estimated Runtime | Required |
|---|---|---|---|---|---|---|
| 1 | MFA Fraud Risk Event Extraction | Step 1 | AADUserRiskEvents, SigninLogs | Extract mfaFraud risk event and matching sign-in | <5s | Yes |
| 2 | MFA Denial Pattern Analysis | Step 2 | SigninLogs | Detect repeated MFA denials (ResultType 500121) via burst analysis | 5-10s | Yes |
| 3 | Denial-Then-Approval Detection | Step 3 | SigninLogs | Detect successful sign-in after MFA denial burst (attack success) | 5-10s | Yes |
| 4 | Baseline Comparison (30-day) | Step 4 | SigninLogs | Establish normal MFA behavior for anomaly comparison | 5-10s | MANDATORY |
| 5 | Post-Approval Session Analysis | Step 5 | SigninLogs | Analyze session after MFA approval (IP, device, apps) | <5s | Yes |
| 6A | Directory Changes and Persistence | Step 6 | AuditLogs | Post-approval MFA registration, OAuth consent, role changes | <5s | Yes |
| 6B | Email and File Activity | Step 6 | OfficeActivity | Post-approval email and file access | 5-10s | Yes |
| 6C | Inbox Rule Deep Dive | Step 6 | OfficeActivity | Inbox rule parameter extraction post-approval | <5s | Yes |
| 7 | Non-Interactive Sign-Ins Post-Approval | Step 7 | AADNonInteractiveUserSignInLogs | Token usage after MFA approval | <5s | Yes |
| 8 | Org-Wide MFA Denial Pattern | Step 8 | SigninLogs | Cross-org MFA denial spike detection (coordinated campaign) | 10-30s | Yes |

## Input Parameters

All queries in this runbook use the following shared input parameters. Replace these values with the actual alert data before running.

```kql
// ============================================================
// SHARED INPUT PARAMETERS - Set these before running any query
// ============================================================
let targetUser = "user@contoso.com";          // UserPrincipalName from the alert
let alertTime = datetime(2026-02-22T14:30:00Z); // TimeGenerated of the risk event or first MFA denial
let alertIP = "203.0.113.50";                 // Source IP triggering MFA prompts (attacker IP)
```

---

## Query 1: MFA Fraud Risk Event Extraction

**Purpose:** Extract the mfaFraud risk event from AADUserRiskEvents and join with SigninLogs via CorrelationId. The mfaFraud event fires when a user reports fraud via the Microsoft Authenticator app. Note: not all MFA fatigue attacks trigger this event -- many are detected only through denial patterns (Query 2).

**Tables:** AADUserRiskEvents, SigninLogs

**Investigation Step:** Step 1

### Production Query

```kql
// ============================================================
// Query 1: MFA Fraud Risk Event Extraction
// Purpose: Pull the mfaFraud risk event and full sign-in context.
//          This event fires when a user taps "No, it wasn't me"
//          or reports fraud via Microsoft Authenticator
// Tables: AADUserRiskEvents, SigninLogs
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-22T14:30:00Z);
let alertIP = "203.0.113.50";
// Lookback window around the alert time to catch the matching sign-in
let lookbackWindow = 2h;
// --- Part 1: Get the mfaFraud risk event ---
// Note: IpAddress uses capital 'A' in AADUserRiskEvents (not IPAddress)
let riskEvent = AADUserRiskEvents
    | where TimeGenerated between ((alertTime - lookbackWindow) .. (alertTime + lookbackWindow))
    | where UserPrincipalName == targetUser
    | where RiskEventType == "mfaFraud"
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
        // MfaDetail parsing - critical for this runbook
        MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "N/A"),
        MfaAuthDetail = iff(isnotempty(MfaDetail), tostring(MfaDetail.authDetail), ""),
        ConditionalAccessStatus,
        // ResultType is a STRING, not int
        ResultType,
        ResultDescription = case(
            ResultType == "0", "Success",
            ResultType == "500121", "MFA denied by user",
            ResultType == "50074", "MFA required - not completed",
            ResultType == "50076", "Strong auth required",
            strcat("Error: ", ResultType)
        ),
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
| DetectionTimingType | string | "realtime" or "offline" |
| RiskLevel | string | "low", "medium", "high" |
| RiskState | string | Current risk state (atRisk, confirmedCompromised, dismissed, etc.) |
| RiskEventType | string | Should be "mfaFraud" |
| UserPrincipalName | string | Affected user |
| IPAddress | string | Source IP that triggered MFA prompts |
| LocationCity | string | City extracted from Location dynamic |
| LocationCountry | string | Country extracted from Location dynamic |
| DeviceOS | string | Operating system of the signing-in device |
| DeviceBrowser | string | Browser used |
| DeviceIsCompliant | string | "true"/"false" - Intune compliance |
| DeviceIsManaged | string | "true"/"false" - managed device |
| DeviceTrustType | string | Trust type (e.g., "AzureAd", "Workplace") |
| UserAgent | string | Raw user agent string |
| AppDisplayName | string | Application accessed |
| ResourceDisplayName | string | Target resource |
| ClientAppUsed | string | Client type (Browser, Mobile Apps, etc.) |
| AuthenticationRequirement | string | "singleFactorAuthentication" or "multiFactorAuthentication" |
| MfaAuthMethod | string | MFA method used or "N/A" |
| MfaAuthDetail | string | MFA detail or empty |
| ConditionalAccessStatus | string | "success", "failure", "notApplied" |
| ResultType | string | "0" = success, "500121" = MFA denied, other = failure code |
| ResultDescription | string | Human-readable result |
| CorrelationId | string | Event correlation GUID |
| SessionId | string | Session identifier |
| SigninTimeGenerated | datetime | Sign-in timestamp |

### Performance Notes

- Query scans a narrow time window (2h around alert time) for both tables - very fast
- CorrelationId inner join ensures only matching records are returned
- Expected result: 1 row (single mfaFraud risk event matched to its sign-in)
- If the join returns 0 rows, the user may not have reported fraud via Authenticator. Proceed to Query 2 for pattern-based detection - that is the primary detection path for MFA fatigue

### Tuning Guidance

- **lookbackWindow**: Default 2h. Increase to 6h if the risk event was an offline detection (DetectionTimingType == "offline")
- **If no CorrelationId match**: Fall back to joining on UserPrincipalName + IPAddress within a 30-minute window
- **mfaFraud vs pattern detection**: Many MFA fatigue attacks do NOT produce an mfaFraud risk event because the user never taps "Report fraud." Query 2 is the primary detection method. This query is supplementary

### Datatable Test Query

```kql
// ============================================================
// TEST: Query 1 - MFA Fraud Risk Event Extraction
// Synthetic data: 3 malicious + 7 benign risk events / sign-ins
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
    // MALICIOUS 1: mfaFraud reported by user (target - should match)
    datetime(2026-02-22T14:32:00Z), "user@contoso.com", "mfaFraud", "high", "atRisk", "realtime",
        "203.0.113.50", dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        "corr-mfa-001", "risk-mfa-001",
    // MALICIOUS 2: mfaFraud for different user (should NOT match target filter)
    datetime(2026-02-22T14:45:00Z), "victim2@contoso.com", "mfaFraud", "high", "atRisk", "realtime",
        "203.0.113.50", dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        "corr-mfa-010", "risk-mfa-010",
    // MALICIOUS 3: unfamiliar features for same user (different risk type - should NOT match)
    datetime(2026-02-22T14:00:00Z), "user@contoso.com", "unfamiliarFeatures", "medium", "atRisk", "realtime",
        "203.0.113.50", dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        "corr-mfa-003", "risk-mfa-003",
    // BENIGN 1: dismissed mfaFraud from last week (outside window - should NOT match)
    datetime(2026-02-15T10:00:00Z), "user@contoso.com", "mfaFraud", "low", "dismissed", "realtime",
        "10.0.0.1", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        "corr-mfa-004", "risk-mfa-004",
    // BENIGN 2: normal sign-in risk for different user
    datetime(2026-02-22T13:00:00Z), "normal@contoso.com", "unfamiliarFeatures", "low", "dismissed", "offline",
        "85.100.50.30", dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        "corr-mfa-005", "risk-mfa-005",
    // BENIGN 3: anonymized IP (wrong risk type)
    datetime(2026-02-22T14:20:00Z), "user@contoso.com", "anonymizedIPAddress", "medium", "atRisk", "realtime",
        "185.220.101.34", dynamic({"city":"","countryOrRegion":"DE"}),
        "corr-mfa-006", "risk-mfa-006",
    // BENIGN 4: different user, different risk type
    datetime(2026-02-22T12:00:00Z), "other@contoso.com", "impossibleTravel", "medium", "atRisk", "realtime",
        "198.51.100.50", dynamic({"city":"Tokyo","countryOrRegion":"JP"}),
        "corr-mfa-007", "risk-mfa-007",
    // BENIGN 5: service account noise
    datetime(2026-02-22T14:10:00Z), "svc.account@contoso.com", "unfamiliarFeatures", "low", "dismissed", "offline",
        "10.1.1.200", dynamic(null),
        "corr-mfa-008", "risk-mfa-008",
    // BENIGN 6: contractor with legitimate MFA denial
    datetime(2026-02-22T09:00:00Z), "contractor@contoso.com", "mfaFraud", "low", "dismissed", "realtime",
        "172.16.0.1", dynamic({"city":"London","countryOrRegion":"GB"}),
        "corr-mfa-009", "risk-mfa-009",
    // BENIGN 7: far outside lookback window
    datetime(2026-02-20T02:00:00Z), "user@contoso.com", "mfaFraud", "low", "dismissed", "offline",
        "203.0.113.50", dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        "corr-mfa-011", "risk-mfa-011"
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
    // MALICIOUS 1: MFA fatigue sign-in attempt (target - should match)
    datetime(2026-02-22T14:31:50Z), "user@contoso.com", "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Windows 10","browser":"Chrome 122.0","isCompliant":"false","isManaged":"false","trustType":""}),
        "Mozilla/5.0 (Windows NT 10.0) Chrome/122.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "failure", "500121", "corr-mfa-001", "sess-mfa-001",
    // MALICIOUS 2: spray target (different user)
    datetime(2026-02-22T14:44:50Z), "victim2@contoso.com", "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Windows 10","browser":"Chrome 122.0","isCompliant":"false","isManaged":"false","trustType":""}),
        "Mozilla/5.0 (Windows NT 10.0) Chrome/122.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "failure", "500121", "corr-mfa-010", "sess-mfa-010",
    // MALICIOUS 3: unfamiliar features sign-in
    datetime(2026-02-22T13:58:00Z), "user@contoso.com", "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Windows 10","browser":"Chrome 122.0","isCompliant":"false","isManaged":"false","trustType":""}),
        "Mozilla/5.0 (Windows NT 10.0) Chrome/122.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-mfa-003", "sess-mfa-003",
    // BENIGN 1: normal user, managed device
    datetime(2026-02-22T13:00:00Z), "normal@contoso.com", "10.0.0.1",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Edge 122.0","isCompliant":"true","isManaged":"true","trustType":"AzureAd"}),
        "Mozilla/5.0 Edg/122.0", "Microsoft Teams", "Microsoft Teams", "Mobile Apps and Desktop clients",
        "multiFactorAuthentication", dynamic({"authMethod":"PhoneAppOTP","authDetail":"Microsoft Authenticator"}),
        "success", "0", "corr-mfa-005", "sess-mfa-005",
    // BENIGN 2: same user, anonymous IP sign-in (wrong correlation)
    datetime(2026-02-22T14:19:00Z), "user@contoso.com", "185.220.101.34",
        dynamic({"city":"","countryOrRegion":"DE"}),
        dynamic({"operatingSystem":"Linux","browser":"Firefox 115.0","isCompliant":"false","isManaged":"false","trustType":""}),
        "Mozilla/5.0 Firefox/115.0", "Azure Portal", "Windows Azure Service Management API", "Browser",
        "singleFactorAuthentication", dynamic(null),
        "notApplied", "0", "corr-mfa-006", "sess-mfa-006",
    // BENIGN 3: outside lookback window
    datetime(2026-02-20T01:59:00Z), "user@contoso.com", "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Windows 10","browser":"Chrome 122.0","isCompliant":"false","isManaged":"false","trustType":""}),
        "Mozilla/5.0 Chrome/122.0", "Microsoft Office 365", "Microsoft Office 365", "Browser",
        "multiFactorAuthentication", dynamic(null),
        "notApplied", "500121", "corr-mfa-011", "sess-mfa-011"
];
// --- Test execution: should return 1 row for user@contoso.com mfaFraud ---
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-22T14:30:00Z);
let alertIP = "203.0.113.50";
let lookbackWindow = 2h;
let riskEvent = testRiskEvents
    | where TimeGenerated between ((alertTime - lookbackWindow) .. (alertTime + lookbackWindow))
    | where UserPrincipalName == targetUser
    | where RiskEventType == "mfaFraud"
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
        MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "N/A"),
        MfaAuthDetail = iff(isnotempty(MfaDetail), tostring(MfaDetail.authDetail), ""),
        ConditionalAccessStatus,
        ResultType,
        ResultDescription = case(
            ResultType == "0", "Success",
            ResultType == "500121", "MFA denied by user",
            ResultType == "50074", "MFA required - not completed",
            strcat("Error: ", ResultType)
        ),
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
// Expected: 1 row - user@contoso.com, high risk, realtime, mfaFraud,
//           RU country, Moscow city, Chrome 122.0, MFA denied (500121)
```

---

## Query 2: MFA Denial Pattern Analysis

**Purpose:** THE UNIQUE QUERY for this runbook. Detect MFA fatigue attacks by identifying users with multiple MFA denials (ResultType == "500121") within short time windows. Uses `bin(TimeGenerated, 5m)` for burst detection. This is the PRIMARY detection method because many MFA fatigue attacks never trigger an mfaFraud risk event.

**Tables:** SigninLogs

**Investigation Step:** Step 2

### Production Query

```kql
// ============================================================
// Query 2: MFA Denial Pattern Analysis
// Purpose: Detect MFA fatigue by finding repeated MFA denials
//          (ResultType 500121) in short time windows. This is
//          the PRIMARY detection method for MFA fatigue attacks.
//          Thresholds: >= 3 denials in 5 min OR >= 5 in 1 hour
// Table: SigninLogs
// Expected runtime: 5-10 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-22T14:30:00Z);
let alertIP = "203.0.113.50";
let analysisWindow = 6h;
// --- Part 1: Get all MFA-related sign-in events for this user ---
let mfaEvents = SigninLogs
    | where TimeGenerated between ((alertTime - analysisWindow) .. (alertTime + analysisWindow))
    | where UserPrincipalName == targetUser
    // MFA denial result codes
    | where ResultType in ("500121", "0", "50074", "50076")
    | extend
        MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "N/A"),
        MfaAuthDetail = iff(isnotempty(MfaDetail), tostring(MfaDetail.authDetail), ""),
        LocationCountry = tostring(Location.countryOrRegion),
        LocationCity = tostring(Location.city),
        MfaResult = case(
            ResultType == "500121", "DENIED",
            ResultType == "0", "APPROVED",
            ResultType == "50074", "MFA_REQUIRED_NOT_COMPLETED",
            ResultType == "50076", "STRONG_AUTH_REQUIRED",
            "OTHER"
        )
    | project
        TimeGenerated,
        UserPrincipalName,
        IPAddress,
        LocationCountry,
        LocationCity,
        AppDisplayName,
        MfaAuthMethod,
        MfaAuthDetail,
        ResultType,
        MfaResult,
        CorrelationId;
// --- Part 2: 5-minute burst analysis ---
let fiveMinBursts = mfaEvents
    | where MfaResult == "DENIED"
    | summarize
        DenialsIn5Min = count(),
        DenialTimes = make_list(TimeGenerated, 100),
        SourceIPs = make_set(IPAddress, 20),
        TargetApps = make_set(AppDisplayName, 20)
        by UserPrincipalName, bin(TimeGenerated, 5m)
    | where DenialsIn5Min >= 3
    | extend
        BurstWindow = "5-minute",
        BurstSeverity = case(
            DenialsIn5Min >= 10, "CRITICAL - Aggressive MFA bombing (10+ in 5 min)",
            DenialsIn5Min >= 5, "HIGH - Strong MFA fatigue pattern (5-9 in 5 min)",
            DenialsIn5Min >= 3, "MEDIUM - Possible MFA fatigue (3-4 in 5 min)",
            "LOW"
        );
// --- Part 3: 1-hour window analysis ---
let oneHourPattern = mfaEvents
    | where MfaResult == "DENIED"
    | summarize
        DenialsIn1Hour = count(),
        DenialTimes = make_list(TimeGenerated, 100),
        SourceIPs = make_set(IPAddress, 20),
        TargetApps = make_set(AppDisplayName, 20),
        DistinctSourceIPs = dcount(IPAddress)
        by UserPrincipalName, bin(TimeGenerated, 1h)
    | where DenialsIn1Hour >= 5
    | extend
        BurstWindow = "1-hour",
        BurstSeverity = case(
            DenialsIn1Hour >= 20, "CRITICAL - Sustained MFA bombing (20+ in 1 hour)",
            DenialsIn1Hour >= 10, "HIGH - Persistent MFA fatigue (10-19 in 1 hour)",
            DenialsIn1Hour >= 5, "MEDIUM - Elevated MFA denials (5-9 in 1 hour)",
            "LOW"
        );
// --- Part 4: Show combined chronological timeline ---
mfaEvents
| order by TimeGenerated asc
| extend
    PrevTime = prev(TimeGenerated),
    PrevResult = prev(MfaResult),
    SecondsSincePrev = datetime_diff("second", TimeGenerated, prev(TimeGenerated))
| extend
    EventPattern = case(
        MfaResult == "DENIED" and isnotempty(SecondsSincePrev) and SecondsSincePrev < 60,
            "RAPID DENIAL - <60s since previous (fatigue indicator)",
        MfaResult == "DENIED" and isnotempty(SecondsSincePrev) and SecondsSincePrev < 300,
            "REPEATED DENIAL - <5min since previous",
        MfaResult == "DENIED",
            "MFA DENIED",
        MfaResult == "APPROVED" and PrevResult == "DENIED",
            "CRITICAL - APPROVED AFTER DENIALS (possible fatigue success)",
        MfaResult == "APPROVED",
            "MFA APPROVED",
        MfaResult
    )
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    LocationCountry,
    AppDisplayName,
    MfaAuthMethod,
    ResultType,
    MfaResult,
    SecondsSincePrev,
    EventPattern,
    CorrelationId
```

### Expected Output Columns

| Column | Type | Description |
|---|---|---|
| TimeGenerated | datetime | Sign-in attempt timestamp |
| UserPrincipalName | string | Target user |
| IPAddress | string | Source IP triggering MFA |
| LocationCountry | string | Country of the source IP |
| AppDisplayName | string | Target application |
| MfaAuthMethod | string | MFA method used (PhoneAppNotification, etc.) |
| ResultType | string | "500121" = MFA denied, "0" = success |
| MfaResult | string | Human-readable: DENIED, APPROVED, etc. |
| SecondsSincePrev | long | Seconds since previous MFA event |
| EventPattern | string | Pattern classification (RAPID DENIAL, fatigue success, etc.) |
| CorrelationId | string | Event correlation GUID |

### Performance Notes

- Scans a 12h window (6h before/after alert) for a single user - fast
- The `bin(TimeGenerated, 5m)` aggregation in Part 2 efficiently detects burst patterns
- The `prev()` function in Part 4 requires prior `order by TimeGenerated asc` for correct sequencing
- Expected result: 5-50 rows showing the MFA denial timeline

### Tuning Guidance

- **analysisWindow**: Default 6h. Expand to 12h for attacks that persist over longer periods
- **5-minute threshold**: Default >= 3 denials. Lower to 2 for more sensitive detection but expect more false positives from legitimate MFA failures (wrong phone, Authenticator app issues)
- **1-hour threshold**: Default >= 5 denials. Adjust based on organizational norms
- **ResultType "500121"**: This is the MFA denial code. Some environments may also see "50074" (MFA required but not completed) which can indicate the user ignored (not denied) the prompt

### Datatable Test Query

```kql
// ============================================================
// TEST: Query 2 - MFA Denial Pattern Analysis
// Synthetic data: MFA fatigue attack pattern with bursts
// ============================================================
let testSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    Location: dynamic,
    AppDisplayName: string,
    MfaDetail: dynamic,
    ResultType: string,
    CorrelationId: string
) [
    // MALICIOUS: MFA fatigue burst - 6 denials in 5 minutes then an approval
    datetime(2026-02-22T14:30:00Z), "user@contoso.com", "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "500121", "corr-burst-001",
    datetime(2026-02-22T14:30:45Z), "user@contoso.com", "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "500121", "corr-burst-002",
    datetime(2026-02-22T14:31:20Z), "user@contoso.com", "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "500121", "corr-burst-003",
    datetime(2026-02-22T14:32:00Z), "user@contoso.com", "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "500121", "corr-burst-004",
    datetime(2026-02-22T14:32:30Z), "user@contoso.com", "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "500121", "corr-burst-005",
    datetime(2026-02-22T14:33:10Z), "user@contoso.com", "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "500121", "corr-burst-006",
    // MALICIOUS: User gives in - approves MFA after fatigue
    datetime(2026-02-22T14:35:00Z), "user@contoso.com", "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "0", "corr-burst-007",
    // BENIGN: Normal user with single MFA denial (typo/wrong phone)
    datetime(2026-02-22T10:00:00Z), "normal@contoso.com", "10.0.0.1",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}), "Microsoft Teams",
        dynamic({"authMethod":"PhoneAppOTP","authDetail":"Microsoft Authenticator"}),
        "500121", "corr-benign-001",
    datetime(2026-02-22T10:01:00Z), "normal@contoso.com", "10.0.0.1",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}), "Microsoft Teams",
        dynamic({"authMethod":"PhoneAppOTP","authDetail":"Microsoft Authenticator"}),
        "0", "corr-benign-002",
    // BENIGN: Different user, successful MFA
    datetime(2026-02-22T12:00:00Z), "other@contoso.com", "85.100.50.30",
        dynamic({"city":"Ankara","countryOrRegion":"TR"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "0", "corr-benign-003"
];
// --- Test execution ---
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-22T14:30:00Z);
let analysisWindow = 6h;
let mfaEvents = testSigninLogs
    | where TimeGenerated between ((alertTime - analysisWindow) .. (alertTime + analysisWindow))
    | where UserPrincipalName == targetUser
    | where ResultType in ("500121", "0", "50074", "50076")
    | extend
        MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "N/A"),
        MfaAuthDetail = iff(isnotempty(MfaDetail), tostring(MfaDetail.authDetail), ""),
        LocationCountry = tostring(Location.countryOrRegion),
        LocationCity = tostring(Location.city),
        MfaResult = case(
            ResultType == "500121", "DENIED",
            ResultType == "0", "APPROVED",
            ResultType == "50074", "MFA_REQUIRED_NOT_COMPLETED",
            ResultType == "50076", "STRONG_AUTH_REQUIRED",
            "OTHER"
        )
    | project
        TimeGenerated,
        UserPrincipalName,
        IPAddress,
        LocationCountry,
        LocationCity,
        AppDisplayName,
        MfaAuthMethod,
        MfaAuthDetail,
        ResultType,
        MfaResult,
        CorrelationId;
mfaEvents
| order by TimeGenerated asc
| extend
    PrevTime = prev(TimeGenerated),
    PrevResult = prev(MfaResult),
    SecondsSincePrev = datetime_diff("second", TimeGenerated, prev(TimeGenerated))
| extend
    EventPattern = case(
        MfaResult == "DENIED" and isnotempty(SecondsSincePrev) and SecondsSincePrev < 60,
            "RAPID DENIAL - <60s since previous (fatigue indicator)",
        MfaResult == "DENIED" and isnotempty(SecondsSincePrev) and SecondsSincePrev < 300,
            "REPEATED DENIAL - <5min since previous",
        MfaResult == "DENIED",
            "MFA DENIED",
        MfaResult == "APPROVED" and PrevResult == "DENIED",
            "CRITICAL - APPROVED AFTER DENIALS (possible fatigue success)",
        MfaResult == "APPROVED",
            "MFA APPROVED",
        MfaResult
    )
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    LocationCountry,
    AppDisplayName,
    MfaAuthMethod,
    ResultType,
    MfaResult,
    SecondsSincePrev,
    EventPattern,
    CorrelationId
// Expected: 7 rows for user@contoso.com
//   6 DENIED events with RAPID DENIAL pattern (30-50 second intervals)
//   1 APPROVED event with "CRITICAL - APPROVED AFTER DENIALS" pattern
```

---

## Query 3: Denial-Then-Approval Detection

**Purpose:** THE CRITICAL PIVOT QUERY. For each user with MFA denials, check if a successful sign-in (ResultType == "0") occurred within 2 hours AFTER the denial burst. This determines if the MFA fatigue attack SUCCEEDED. Uses a self-join approach to correlate denial windows with subsequent approvals.

**Tables:** SigninLogs

**Investigation Step:** Step 3

### Production Query

```kql
// ============================================================
// Query 3: Denial-Then-Approval Detection
// Purpose: Determine if the MFA fatigue attack SUCCEEDED by
//          checking for a successful sign-in after the denial
//          burst. This is the CRITICAL pivot - if there is an
//          approval after denials, the account is compromised
// Table: SigninLogs
// Expected runtime: 5-10 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-22T14:30:00Z);
let alertIP = "203.0.113.50";
let analysisWindow = 6h;
// Window after last denial to check for approval
let approvalWindow = 2h;
// --- Part 1: Find the denial burst summary ---
let denialBursts = SigninLogs
    | where TimeGenerated between ((alertTime - analysisWindow) .. (alertTime + analysisWindow))
    | where UserPrincipalName == targetUser
    | where ResultType == "500121"
    | summarize
        DenialCount = count(),
        FirstDenial = min(TimeGenerated),
        LastDenial = max(TimeGenerated),
        DenialIPs = make_set(IPAddress, 20),
        DenialCountries = make_set(tostring(Location.countryOrRegion), 10),
        DenialApps = make_set(AppDisplayName, 20),
        DenialMethods = make_set(iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "N/A"), 10),
        BurstDurationSeconds = datetime_diff("second", max(TimeGenerated), min(TimeGenerated))
        by UserPrincipalName;
// --- Part 2: Find successful sign-ins AFTER denials ---
let postDenialApprovals = SigninLogs
    | where TimeGenerated between ((alertTime - analysisWindow) .. (alertTime + analysisWindow + approvalWindow))
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | extend
        DeviceOS = tostring(DeviceDetail.operatingSystem),
        DeviceBrowser = tostring(DeviceDetail.browser),
        DeviceIsCompliant = tostring(DeviceDetail.isCompliant),
        DeviceIsManaged = tostring(DeviceDetail.isManaged),
        LocationCountry = tostring(Location.countryOrRegion),
        LocationCity = tostring(Location.city),
        MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "N/A"),
        MfaAuthDetail = iff(isnotempty(MfaDetail), tostring(MfaDetail.authDetail), "")
    | project
        ApprovalTime = TimeGenerated,
        UserPrincipalName,
        ApprovalIP = IPAddress,
        ApprovalCountry = LocationCountry,
        ApprovalCity = LocationCity,
        ApprovalApp = AppDisplayName,
        ApprovalResource = ResourceDisplayName,
        ApprovalMfaMethod = MfaAuthMethod,
        ApprovalMfaDetail = MfaAuthDetail,
        ApprovalDeviceOS = DeviceOS,
        ApprovalDeviceBrowser = DeviceBrowser,
        ApprovalDeviceCompliant = DeviceIsCompliant,
        ApprovalDeviceManaged = DeviceIsManaged,
        ApprovalSessionId = SessionId,
        ApprovalCorrelationId = CorrelationId;
// --- Part 3: Join denials with post-denial approvals ---
denialBursts
| join kind=inner postDenialApprovals on UserPrincipalName
// Only approvals that came AFTER the last denial
| where ApprovalTime > LastDenial
// Only approvals within the approval window
| where ApprovalTime < (LastDenial + approvalWindow)
| extend
    MinutesBetweenLastDenialAndApproval = datetime_diff("minute", ApprovalTime, LastDenial),
    // Check if approval came from same IP as denials (attacker got through)
    ApprovalFromDenialIP = iff(ApprovalIP in (DenialIPs), "YES - SAME IP AS DENIALS", "NO - Different IP"),
    // Risk assessment
    CompromiseAssessment = case(
        // Approval from same IP that was denied = attacker succeeded
        ApprovalIP in (DenialIPs) and DenialCount >= 5,
            "CRITICAL - MFA FATIGUE SUCCEEDED: Approval from attacker IP after 5+ denials",
        ApprovalIP in (DenialIPs) and DenialCount >= 3,
            "HIGH - LIKELY MFA FATIGUE: Approval from attacker IP after multiple denials",
        // Approval from different IP but right after denials = possible social engineering
        ApprovalIP !in (DenialIPs) and datetime_diff("minute", ApprovalTime, LastDenial) < 10,
            "HIGH - SUSPICIOUS: Approval from different IP within 10min of denials (social engineering?)",
        // Approval much later = possibly legitimate
        datetime_diff("minute", ApprovalTime, LastDenial) > 60,
            "LOW - Approval came >1 hour after denials (likely legitimate separate sign-in)",
        "MEDIUM - Review approval context"
    )
| project
    UserPrincipalName,
    // Denial burst context
    DenialCount,
    FirstDenial,
    LastDenial,
    BurstDurationSeconds,
    DenialIPs,
    DenialCountries,
    DenialApps,
    DenialMethods,
    // Approval context
    ApprovalTime,
    MinutesBetweenLastDenialAndApproval,
    ApprovalIP,
    ApprovalCountry,
    ApprovalCity,
    ApprovalApp,
    ApprovalResource,
    ApprovalMfaMethod,
    ApprovalDeviceOS,
    ApprovalDeviceBrowser,
    ApprovalDeviceCompliant,
    ApprovalDeviceManaged,
    // Correlation
    ApprovalFromDenialIP,
    CompromiseAssessment,
    ApprovalSessionId,
    ApprovalCorrelationId
| order by ApprovalTime asc
```

### Expected Output Columns

| Column | Type | Description |
|---|---|---|
| UserPrincipalName | string | Target user |
| DenialCount | long | Total MFA denials in the burst |
| FirstDenial / LastDenial | datetime | Denial burst time range |
| BurstDurationSeconds | long | Duration of the denial burst |
| DenialIPs | dynamic | Set of IPs that triggered denials |
| DenialCountries | dynamic | Countries of denial source IPs |
| DenialApps | dynamic | Applications targeted during denials |
| DenialMethods | dynamic | MFA methods used during denials |
| ApprovalTime | datetime | When the successful sign-in occurred |
| MinutesBetweenLastDenialAndApproval | long | Gap between last denial and approval |
| ApprovalIP | string | IP of the successful sign-in |
| ApprovalFromDenialIP | string | Whether approval came from the same IP as denials |
| CompromiseAssessment | string | Risk classification |
| ApprovalSessionId | string | Session ID of the approved sign-in (use for blast radius) |

### Performance Notes

- Scans a 12h+ window for a single user - fast
- The inner join between denial bursts and approvals produces results ONLY when both denials AND subsequent approvals exist
- Expected result: 0 rows (attack failed, no approval) or 1+ rows (attack may have succeeded)
- If 0 rows: the user resisted the fatigue attack. Document and close
- If 1+ rows: ESCALATE immediately and proceed to Queries 5-7 for blast radius

### Tuning Guidance

- **approvalWindow**: Default 2h. Some attackers persist for hours -- extend to 4h for thorough investigation
- **CompromiseAssessment logic**: The "same IP as denials" check is the strongest indicator. If the approval came from a different IP but within minutes of denials, consider social engineering (attacker called the user and asked them to approve)
- **Multiple approvals**: If multiple approval rows are returned, the FIRST one is the initial compromise point. Use its SessionId for all blast radius queries

### Datatable Test Query

```kql
// ============================================================
// TEST: Query 3 - Denial-Then-Approval Detection
// Synthetic data: Denial burst followed by approval
// ============================================================
let testSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    Location: dynamic,
    DeviceDetail: dynamic,
    AppDisplayName: string,
    ResourceDisplayName: string,
    MfaDetail: dynamic,
    ResultType: string,
    SessionId: string,
    CorrelationId: string
) [
    // DENIAL BURST: 6 denials in 3 minutes from attacker IP
    datetime(2026-02-22T14:30:00Z), "user@contoso.com", "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Windows 10","browser":"Chrome 122.0","isCompliant":"false","isManaged":"false"}),
        "Microsoft Office 365", "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "500121", "sess-deny-001", "corr-deny-001",
    datetime(2026-02-22T14:30:45Z), "user@contoso.com", "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Windows 10","browser":"Chrome 122.0","isCompliant":"false","isManaged":"false"}),
        "Microsoft Office 365", "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "500121", "sess-deny-002", "corr-deny-002",
    datetime(2026-02-22T14:31:20Z), "user@contoso.com", "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Windows 10","browser":"Chrome 122.0","isCompliant":"false","isManaged":"false"}),
        "Microsoft Office 365", "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "500121", "sess-deny-003", "corr-deny-003",
    datetime(2026-02-22T14:32:00Z), "user@contoso.com", "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Windows 10","browser":"Chrome 122.0","isCompliant":"false","isManaged":"false"}),
        "Microsoft Office 365", "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "500121", "sess-deny-004", "corr-deny-004",
    datetime(2026-02-22T14:32:30Z), "user@contoso.com", "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Windows 10","browser":"Chrome 122.0","isCompliant":"false","isManaged":"false"}),
        "Microsoft Office 365", "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "500121", "sess-deny-005", "corr-deny-005",
    datetime(2026-02-22T14:33:10Z), "user@contoso.com", "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Windows 10","browser":"Chrome 122.0","isCompliant":"false","isManaged":"false"}),
        "Microsoft Office 365", "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "500121", "sess-deny-006", "corr-deny-006",
    // APPROVAL: User gives in 2 minutes after last denial - from SAME attacker IP
    datetime(2026-02-22T14:35:00Z), "user@contoso.com", "203.0.113.50",
        dynamic({"city":"Moscow","countryOrRegion":"RU"}),
        dynamic({"operatingSystem":"Windows 10","browser":"Chrome 122.0","isCompliant":"false","isManaged":"false"}),
        "Microsoft Office 365", "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification","authDetail":"Microsoft Authenticator"}),
        "0", "sess-approve-001", "corr-approve-001",
    // BENIGN: Normal user sign-in (no denial history)
    datetime(2026-02-22T12:00:00Z), "normal@contoso.com", "10.0.0.1",
        dynamic({"city":"Istanbul","countryOrRegion":"TR"}),
        dynamic({"operatingSystem":"Windows 11","browser":"Edge 122.0","isCompliant":"true","isManaged":"true"}),
        "Microsoft Teams", "Microsoft Teams",
        dynamic({"authMethod":"PhoneAppOTP","authDetail":"Microsoft Authenticator"}),
        "0", "sess-benign-001", "corr-benign-001"
];
// --- Test execution ---
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-22T14:30:00Z);
let analysisWindow = 6h;
let approvalWindow = 2h;
let denialBursts = testSigninLogs
    | where TimeGenerated between ((alertTime - analysisWindow) .. (alertTime + analysisWindow))
    | where UserPrincipalName == targetUser
    | where ResultType == "500121"
    | summarize
        DenialCount = count(),
        FirstDenial = min(TimeGenerated),
        LastDenial = max(TimeGenerated),
        DenialIPs = make_set(IPAddress, 20),
        DenialCountries = make_set(tostring(Location.countryOrRegion), 10),
        DenialApps = make_set(AppDisplayName, 20),
        DenialMethods = make_set(iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "N/A"), 10),
        BurstDurationSeconds = datetime_diff("second", max(TimeGenerated), min(TimeGenerated))
        by UserPrincipalName;
let postDenialApprovals = testSigninLogs
    | where TimeGenerated between ((alertTime - analysisWindow) .. (alertTime + analysisWindow + approvalWindow))
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | extend
        LocationCountry = tostring(Location.countryOrRegion),
        LocationCity = tostring(Location.city),
        MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "N/A"),
        MfaAuthDetail = iff(isnotempty(MfaDetail), tostring(MfaDetail.authDetail), "")
    | project
        ApprovalTime = TimeGenerated,
        UserPrincipalName,
        ApprovalIP = IPAddress,
        ApprovalCountry = LocationCountry,
        ApprovalCity = LocationCity,
        ApprovalApp = AppDisplayName,
        ApprovalResource = ResourceDisplayName,
        ApprovalMfaMethod = MfaAuthMethod,
        ApprovalMfaDetail = MfaAuthDetail,
        ApprovalDeviceOS = tostring(DeviceDetail.operatingSystem),
        ApprovalDeviceBrowser = tostring(DeviceDetail.browser),
        ApprovalDeviceCompliant = tostring(DeviceDetail.isCompliant),
        ApprovalDeviceManaged = tostring(DeviceDetail.isManaged),
        ApprovalSessionId = SessionId,
        ApprovalCorrelationId = CorrelationId;
denialBursts
| join kind=inner postDenialApprovals on UserPrincipalName
| where ApprovalTime > LastDenial
| where ApprovalTime < (LastDenial + approvalWindow)
| extend
    MinutesBetweenLastDenialAndApproval = datetime_diff("minute", ApprovalTime, LastDenial),
    ApprovalFromDenialIP = iff(ApprovalIP in (DenialIPs), "YES - SAME IP AS DENIALS", "NO - Different IP"),
    CompromiseAssessment = case(
        ApprovalIP in (DenialIPs) and DenialCount >= 5,
            "CRITICAL - MFA FATIGUE SUCCEEDED: Approval from attacker IP after 5+ denials",
        ApprovalIP in (DenialIPs) and DenialCount >= 3,
            "HIGH - LIKELY MFA FATIGUE: Approval from attacker IP after multiple denials",
        ApprovalIP !in (DenialIPs) and datetime_diff("minute", ApprovalTime, LastDenial) < 10,
            "HIGH - SUSPICIOUS: Approval from different IP within 10min of denials",
        datetime_diff("minute", ApprovalTime, LastDenial) > 60,
            "LOW - Approval came >1 hour after denials (likely legitimate)",
        "MEDIUM - Review approval context"
    )
| project
    UserPrincipalName,
    DenialCount,
    FirstDenial,
    LastDenial,
    BurstDurationSeconds,
    DenialIPs,
    DenialCountries,
    DenialApps,
    DenialMethods,
    ApprovalTime,
    MinutesBetweenLastDenialAndApproval,
    ApprovalIP,
    ApprovalFromDenialIP,
    CompromiseAssessment,
    ApprovalSessionId,
    ApprovalCorrelationId
| order by ApprovalTime asc
// Expected: 1 row
//   DenialCount = 6, BurstDurationSeconds = 190 (3min 10s)
//   ApprovalTime = 14:35:00, MinutesBetweenLastDenialAndApproval = 1
//   ApprovalFromDenialIP = "YES - SAME IP AS DENIALS"
//   CompromiseAssessment = "CRITICAL - MFA FATIGUE SUCCEEDED"
```

---

## Query 4: Baseline Comparison - Establish Normal MFA Behavior Pattern

**Purpose:** Build a 30-day behavioral baseline for the user's MFA challenge/deny/approve ratio and compare the flagged activity against it. This is the MANDATORY baseline step. A user who normally has 0 MFA denials per day suddenly having 10 is anomalous. Also calculates typical time between MFA challenge and approval, normal sign-in hours, and MFA methods registered.

**Tables:** SigninLogs

**Investigation Step:** Step 4 (MANDATORY)

### Production Query

```kql
// ============================================================
// Query 4: MFA Behavior Baseline (30-day) - MANDATORY
// Purpose: Calculate what "normal" MFA behavior looks like for
//          this user over the past 30 days. Compare denial
//          counts, approval ratios, and timing patterns to
//          determine if the current activity is anomalous
// Table: SigninLogs
// MANDATORY - Do not skip this query
// Expected runtime: 5-10 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-22T14:30:00Z);
let baselinePeriod = 30d;
// Baseline window: 30d ago to 1d ago (exclude recent day to avoid contamination)
let baselineStart = alertTime - baselinePeriod;
let baselineEnd = alertTime - 1d;
// --- Part 1: Daily MFA denial/approval counts over baseline ---
let dailyMfaBaseline = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType in ("500121", "0", "50074", "50076")
    | summarize
        TotalAttempts = count(),
        MfaDenials = countif(ResultType == "500121"),
        MfaApprovals = countif(ResultType == "0"),
        MfaIncomplete = countif(ResultType in ("50074", "50076")),
        DistinctIPs = dcount(IPAddress),
        DistinctCountries = dcount(tostring(Location.countryOrRegion)),
        DistinctApps = dcount(AppDisplayName),
        MfaMethods = make_set(iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), ""), 10)
        by bin(TimeGenerated, 1d);
// --- Part 2: Calculate statistical baseline from daily aggregates ---
let baselineStats = dailyMfaBaseline
    | summarize
        BaselineDays = count(),
        // Denial statistics
        AvgDailyDenials = round(avg(MfaDenials), 2),
        StdevDailyDenials = round(stdev(MfaDenials), 2),
        MaxDailyDenials = max(MfaDenials),
        TotalBaselineDenials = sum(MfaDenials),
        // Approval statistics
        AvgDailyApprovals = round(avg(MfaApprovals), 2),
        TotalBaselineApprovals = sum(MfaApprovals),
        // Overall MFA attempt statistics
        AvgDailyAttempts = round(avg(TotalAttempts), 2),
        MaxDailyAttempts = max(TotalAttempts),
        // IP and location diversity
        AvgDistinctIPs = round(avg(DistinctIPs), 2),
        MaxDistinctIPs = max(DistinctIPs);
// --- Part 3: Known MFA methods in baseline ---
let knownMfaMethods = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | where isnotempty(MfaDetail)
    | distinct tostring(MfaDetail.authMethod);
// --- Part 4: Typical sign-in hours ---
let typicalHours = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | extend HourOfDay = hourofday(TimeGenerated)
    | summarize SigninsPerHour = count() by HourOfDay
    | order by SigninsPerHour desc
    | take 5;
// --- Part 5: Current alert day MFA activity ---
let alertDayActivity = SigninLogs
    | where TimeGenerated between (startofday(alertTime) .. endofday(alertTime))
    | where UserPrincipalName == targetUser
    | where ResultType in ("500121", "0", "50074", "50076")
    | summarize
        AlertDayDenials = countif(ResultType == "500121"),
        AlertDayApprovals = countif(ResultType == "0"),
        AlertDayTotal = count(),
        AlertDayIPs = make_set(IPAddress, 20),
        AlertDayCountries = make_set(tostring(Location.countryOrRegion), 10);
// --- Part 6: Produce the comparison output ---
baselineStats
| extend placeholder = 1
| join kind=inner (alertDayActivity | extend placeholder = 1) on placeholder
| project-away placeholder, placeholder1
| extend
    // Calculate how anomalous the alert day is
    DenialZScore = iff(
        StdevDailyDenials > 0,
        round((toreal(AlertDayDenials) - AvgDailyDenials) / StdevDailyDenials, 2),
        iff(AlertDayDenials > 0, 99.0, 0.0)
    ),
    DenialMultiplier = iff(
        AvgDailyDenials > 0,
        round(toreal(AlertDayDenials) / AvgDailyDenials, 1),
        iff(AlertDayDenials > 0, toreal(AlertDayDenials), 0.0)
    ),
    // Baseline denial rate
    BaselineDenialRate = iff(
        TotalBaselineApprovals + TotalBaselineDenials > 0,
        round(100.0 * TotalBaselineDenials / (TotalBaselineApprovals + TotalBaselineDenials), 2),
        0.0
    ),
    // Alert day denial rate
    AlertDayDenialRate = iff(
        AlertDayTotal > 0,
        round(100.0 * AlertDayDenials / AlertDayTotal, 2),
        0.0
    ),
    // Anomaly assessment
    AnomalyAssessment = case(
        // Zero baseline denials + multiple denials today = extreme anomaly
        TotalBaselineDenials == 0 and AlertDayDenials >= 3,
            "CRITICAL ANOMALY - User has ZERO MFA denials in 30 days, today has multiple",
        // Z-score based anomaly
        StdevDailyDenials > 0 and (toreal(AlertDayDenials) - AvgDailyDenials) / StdevDailyDenials > 3,
            "HIGH ANOMALY - Alert day denials are >3 standard deviations above normal",
        // Multiplier based anomaly
        AvgDailyDenials > 0 and toreal(AlertDayDenials) / AvgDailyDenials > 5,
            "HIGH ANOMALY - Alert day denials are 5x+ above daily average",
        // Moderate anomaly
        AlertDayDenials > MaxDailyDenials and MaxDailyDenials > 0,
            "MEDIUM ANOMALY - Alert day exceeds historical maximum denials",
        // Low or no baseline
        BaselineDays < 7,
            "INSUFFICIENT BASELINE - Less than 7 days of data (new account risk)",
        AlertDayDenials <= MaxDailyDenials and AlertDayDenials > 0,
            "LOW ANOMALY - Alert day denials within historical range",
        AlertDayDenials == 0,
            "NO DENIALS - No MFA denials on alert day",
        "REVIEW REQUIRED"
    ),
    HasHistoricalDenials = iff(TotalBaselineDenials > 0,
        strcat("YES - ", TotalBaselineDenials, " total denials in ", BaselineDays, " days"),
        "NO - Zero MFA denials in entire baseline period")
| project
    UserPrincipalName = targetUser,
    // Baseline statistics
    BaselineDays,
    AvgDailyDenials,
    StdevDailyDenials,
    MaxDailyDenials,
    TotalBaselineDenials,
    AvgDailyApprovals,
    TotalBaselineApprovals,
    BaselineDenialRate,
    HasHistoricalDenials,
    // Alert day comparison
    AlertDayDenials,
    AlertDayApprovals,
    AlertDayTotal,
    AlertDayDenialRate,
    AlertDayIPs,
    AlertDayCountries,
    // Statistical comparison
    DenialZScore,
    DenialMultiplier,
    // Final assessment
    AnomalyAssessment
```

### Expected Output Columns

| Column | Type | Description |
|---|---|---|
| UserPrincipalName | string | Target user |
| BaselineDays | long | Number of days in baseline |
| AvgDailyDenials | double | Average MFA denials per day in baseline |
| StdevDailyDenials | double | Standard deviation of daily denials |
| MaxDailyDenials | long | Maximum denials in a single day (baseline) |
| TotalBaselineDenials | long | Total denials across entire baseline |
| AvgDailyApprovals | double | Average successful MFA approvals per day |
| TotalBaselineApprovals | long | Total approvals in baseline |
| BaselineDenialRate | double | Percentage of MFA attempts that were denials (baseline) |
| HasHistoricalDenials | string | Whether user has any prior MFA denial history |
| AlertDayDenials | long | Denials on the alert day |
| AlertDayApprovals | long | Approvals on the alert day |
| AlertDayDenialRate | double | Denial rate on alert day |
| AlertDayIPs | dynamic | IPs seen on alert day |
| AlertDayCountries | dynamic | Countries seen on alert day |
| DenialZScore | double | Z-score of alert day denials vs baseline (>3 = highly anomalous) |
| DenialMultiplier | double | How many times above average the alert day denials are |
| AnomalyAssessment | string | Overall anomaly classification |

### Performance Notes

- Scans 30 days of SigninLogs for a single user - moderate volume
- The daily aggregation (Part 1) reduces data before statistical calculations
- The z-score calculation handles edge cases: zero stdev (constant baseline) and zero average
- Expected result: 1 row with comprehensive baseline comparison

### Tuning Guidance

- **baselinePeriod**: Default 30d. Use 14d for high-volume accounts, 60d for infrequent users
- **Z-score threshold**: A z-score > 3 means the alert day is more than 3 standard deviations above normal, which is statistically significant. Adjust to > 2 for more sensitive detection
- **Zero-baseline users**: Most enterprise users have 0 MFA denials in their baseline. ANY denial burst for these users is anomalous
- **INSUFFICIENT BASELINE**: If BaselineDays < 7, the user account is new or rarely active. Treat any MFA denial burst as suspicious regardless of statistical comparison

---

## Query 5: Post-Approval Session Analysis

**Purpose:** If MFA was approved after denials (Query 3 returned results), analyze the approved session. Compare the approval IP, location, and device against the denial context. Check if the approval came from a DIFFERENT device/IP than the denials, which indicates the user approved on their legitimate device while the attacker's session on a different device received the token.

**Tables:** SigninLogs

**Investigation Step:** Step 5

### Production Query

```kql
// ============================================================
// Query 5: Post-Approval Session Analysis
// Purpose: Analyze the session established after MFA approval.
//          Compare approval device/IP with denial device/IP to
//          determine if the user approved the attacker's session
//          or their own. Check all apps accessed post-approval
// Table: SigninLogs
// Prerequisite: Run Query 3 first. Use the ApprovalTime and
//               ApprovalSessionId from Query 3 as input
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertTime = datetime(2026-02-22T14:30:00Z);
let alertIP = "203.0.113.50";
// Use the approval time from Query 3 results
let approvalTime = datetime(2026-02-22T14:35:00Z);
// Post-approval analysis window
let postApprovalWindow = 4h;
// --- Part 1: All sign-in activity after the MFA approval ---
let postApprovalActivity = SigninLogs
    | where TimeGenerated between (approvalTime .. (approvalTime + postApprovalWindow))
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | extend
        DeviceOS = tostring(DeviceDetail.operatingSystem),
        DeviceBrowser = tostring(DeviceDetail.browser),
        DeviceIsCompliant = tostring(DeviceDetail.isCompliant),
        DeviceIsManaged = tostring(DeviceDetail.isManaged),
        DeviceTrustType = tostring(DeviceDetail.trustType),
        LocationCountry = tostring(Location.countryOrRegion),
        LocationCity = tostring(Location.city),
        MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "N/A"),
        MfaAuthDetail = iff(isnotempty(MfaDetail), tostring(MfaDetail.authDetail), "");
// --- Part 2: Compare each post-approval sign-in to the alert IP ---
postApprovalActivity
| extend
    MinutesAfterApproval = datetime_diff("minute", TimeGenerated, approvalTime),
    IsFromAttackerIP = iff(IPAddress == alertIP, "YES - ATTACKER IP", "No"),
    // Check for suspicious patterns
    SessionRisk = case(
        // Accessing sensitive resources from attacker IP
        IPAddress == alertIP and AppDisplayName in (
            "Azure Portal", "Microsoft Azure Management",
            "Microsoft Graph", "Office 365 Exchange Online",
            "Microsoft Admin Center", "Azure Active Directory PowerShell"),
            "CRITICAL - Sensitive resource access from attacker IP",
        // Any access from attacker IP post-approval
        IPAddress == alertIP,
            "HIGH - Active session from attacker IP post-approval",
        // Access from unmanaged device post-approval
        DeviceIsManaged == "false" and DeviceIsCompliant == "false",
            "MEDIUM - Unmanaged/non-compliant device access post-approval",
        "LOW - Access from known/managed device"
    )
| project
    TimeGenerated,
    MinutesAfterApproval,
    UserPrincipalName,
    IPAddress,
    IsFromAttackerIP,
    LocationCountry,
    LocationCity,
    AppDisplayName,
    ResourceDisplayName,
    ClientAppUsed,
    DeviceOS,
    DeviceBrowser,
    DeviceIsCompliant,
    DeviceIsManaged,
    DeviceTrustType,
    AuthenticationRequirement,
    MfaAuthMethod,
    SessionRisk,
    SessionId,
    CorrelationId
| order by TimeGenerated asc
```

### Expected Output Columns

| Column | Type | Description |
|---|---|---|
| TimeGenerated | datetime | Sign-in timestamp |
| MinutesAfterApproval | long | Minutes after the MFA approval |
| IPAddress | string | Source IP of the sign-in |
| IsFromAttackerIP | string | Whether sign-in came from the attacker IP |
| LocationCountry / LocationCity | string | Location of the sign-in |
| AppDisplayName | string | Application accessed |
| DeviceOS / DeviceBrowser | string | Device details |
| DeviceIsCompliant / DeviceIsManaged | string | Device compliance state |
| SessionRisk | string | Risk classification |
| SessionId | string | Session identifier |

### Performance Notes

- Scans a 4h window for a single user with success filter - very fast
- Expected result: 1-20 rows showing all applications accessed after MFA approval
- Focus on rows where `IsFromAttackerIP == "YES"` - these are the attacker's active sessions

### Tuning Guidance

- **approvalTime**: Must come from Query 3 results. Do not estimate
- **postApprovalWindow**: Default 4h. Extend to 24h to see the full scope of post-compromise activity
- **Sensitive app list**: Customize the AppDisplayName list in SessionRisk based on organizational critical applications
- **Device comparison**: If the approval came from a managed device but subsequent access is from an unmanaged device, the attacker likely received the token on their device while the user approved on theirs

---

## Query 6A: Directory Changes and Persistence After MFA Approval

**Purpose:** Check for persistence mechanisms created via directory operations AFTER the MFA approval. Attackers who succeed via MFA fatigue immediately register new MFA methods, grant OAuth consent, or escalate privileges to maintain access after the session expires.

**Tables:** AuditLogs

**Investigation Step:** Step 6

### Production Query

```kql
// ============================================================
// Query 6A: Directory Changes and Persistence After MFA Approval
// Purpose: Check for persistence mechanisms created via
//          directory operations AFTER the MFA fatigue approval.
//          Key indicators: new MFA method registration, OAuth
//          app consent, role escalation
// Table: AuditLogs
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
// Use the MFA approval time from Query 3 results
let approvalTime = datetime(2026-02-22T14:35:00Z);
// 4-hour window per Hasan's recommendation (accounts for latency)
let postApprovalWindow = 4h;
AuditLogs
| where TimeGenerated between (approvalTime .. (approvalTime + postApprovalWindow))
// Filter for high-risk operations
| where OperationName in (
    // MFA / authentication persistence - CRITICAL for MFA fatigue followup
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
    MinutesAfterApproval = datetime_diff("minute", TimeGenerated, approvalTime),
    // Severity classification for post-MFA-approval activity
    Severity = case(
        OperationName has "security info", "CRITICAL - MFA METHOD MANIPULATION (post-fatigue persistence)",
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

### Expected Output Columns

| Column | Type | Description |
|---|---|---|
| TimeGenerated | datetime | When the operation occurred |
| OperationName | string | What was changed |
| InitiatedByUser | string | Who initiated the change |
| TargetUPN | string | Who was affected |
| ModifiedProperties | dynamic | What was modified |
| MinutesAfterApproval | long | Minutes after MFA approval |
| Severity | string | Risk classification |

### Performance Notes

- Scans 4 hours of AuditLogs filtered by specific OperationName values - very fast
- The `"User registered security info"` operation is the most critical indicator for MFA fatigue followup -- if the attacker registers their own MFA method, they maintain access permanently
- Expected result: 0 rows (no persistence) or 1-5 rows if the attacker established persistence

### Tuning Guidance

- **postApprovalWindow**: Default 4h. For fast triage use 2h. For thorough investigation expand to 24h
- **MFA method registration**: If you see `"User registered security info"` within minutes of the MFA approval, the attacker is registering their own Authenticator app. This is an IMMEDIATE containment trigger
- **If the alert is very recent** (<1 hour): AuditLogs entries may still be ingesting. Re-run after 2 hours

---

## Query 6B: Email and File Activity After MFA Approval

**Purpose:** Check for inbox rule creation, email forwarding, bulk email access, and file exfiltration patterns AFTER the MFA fatigue approval. Attackers who compromise accounts via MFA fatigue often immediately set up email forwarding for BEC or download sensitive files.

**Tables:** OfficeActivity

**Investigation Step:** Step 6

### Production Query

```kql
// ============================================================
// Query 6B: Email and File Activity After MFA Approval
// Purpose: Check for inbox rule creation, email forwarding,
//          bulk email access, and file exfiltration patterns
//          AFTER the MFA fatigue approval
// Table: OfficeActivity
// Note: OfficeActivity has up to 60 min ingestion latency.
//       If the alert is <1 hour old, results may be incomplete.
//       Re-run this query after 1-2 hours for full coverage.
// Expected runtime: 5-10 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertIP = "203.0.113.50";
// Use the MFA approval time from Query 3 results
let approvalTime = datetime(2026-02-22T14:35:00Z);
// 4-hour window per Hasan's latency guidance
let postApprovalWindow = 4h;
OfficeActivity
| where TimeGenerated between (approvalTime .. (approvalTime + postApprovalWindow))
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
    MinutesAfterApproval = datetime_diff("minute", TimeGenerated, approvalTime),
    // Flag if activity came from the attacker IP specifically
    FromAttackerIP = iff(CleanClientIP == alertIP, "YES - FROM ATTACKER IP", "No - different IP"),
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
| FromAttackerIP | string | Whether this activity came from the attacker IP |
| MinutesAfterApproval | long | Minutes after the MFA approval |
| RiskCategory | string | Severity classification |

### Performance Notes

- Scans 4 hours of OfficeActivity for a single user - fast
- MailItemsAccessed can generate very high volume in E5 environments
- The `extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)` regex normalizes all ClientIP formats to plain IPv4

### Tuning Guidance

- **postApprovalWindow**: Default 4h. For fast triage use 2h but note potential data gaps due to OfficeActivity ingestion latency
- **FromAttackerIP filter**: Add `| where FromAttackerIP == "YES - FROM ATTACKER IP"` to focus only on activity from the attacker IP specifically
- **MailItemsAccessed volume**: In E5 environments, add `| where Operation != "MailItemsAccessed"` for initial triage, then run separately for email access analysis

---

## Query 6C: Inbox Rule Deep Dive After MFA Approval

**Purpose:** Extract detailed inbox rule parameters to determine if rules created after MFA approval are malicious (forwarding to external addresses, deleting messages, hiding emails with financial keywords). This is the primary persistence mechanism attackers establish after MFA fatigue compromise.

**Tables:** OfficeActivity

**Investigation Step:** Step 6

### Production Query

```kql
// ============================================================
// Query 6C: Inbox Rule Deep Dive After MFA Approval
// Purpose: Extract inbox rule creation details post-approval.
//          Attackers who succeed via MFA fatigue often immediately
//          create inbox rules to intercept emails before the
//          account owner notices compromise
// Table: OfficeActivity
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
// Use the MFA approval time from Query 3 results
let approvalTime = datetime(2026-02-22T14:35:00Z);
let postApprovalWindow = 4h;
OfficeActivity
| where TimeGenerated between (approvalTime .. (approvalTime + postApprovalWindow))
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
    MinutesAfterApproval = datetime_diff("minute", TimeGenerated, approvalTime),
    // Flag malicious patterns
    IsMalicious = iff(
        isnotempty(ForwardTo) or isnotempty(ForwardAsAttachmentTo) or isnotempty(RedirectTo)
        or DeleteMessage == "True" or MarkAsRead == "True"
        or SubjectContainsWords has_any ("invoice", "payment", "wire", "transfer", "urgent", "password", "security", "MFA", "verification"),
        "LIKELY MALICIOUS",
        "REVIEW REQUIRED"
    )
| project
    TimeGenerated,
    MinutesAfterApproval,
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
| MinutesAfterApproval | long | Minutes after MFA approval |
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
- **Timing**: Inbox rules created within 30 minutes of MFA approval are extremely suspicious. Rules created hours later may be legitimate user activity

---

## Query 7: Non-Interactive Sign-Ins After MFA Approval

**Purpose:** Check for non-interactive (token-based) sign-ins after the MFA approval. Once an attacker gets past MFA via fatigue, they receive tokens that can be refreshed without additional MFA. This query detects ongoing attacker session persistence via token refresh activity.

**Tables:** AADNonInteractiveUserSignInLogs

**Investigation Step:** Step 7

### Production Query

```kql
// ============================================================
// Query 7: Non-Interactive Sign-Ins After MFA Approval
// Purpose: Detect token replay or session persistence by
//          checking for non-interactive sign-ins after MFA
//          approval. These indicate ongoing access via refresh
//          tokens. Critical for MFA fatigue because the
//          attacker's tokens persist even after detection
// Table: AADNonInteractiveUserSignInLogs
// Note: This table is HIGH VOLUME - always filter by user + IP
//       (Hasan's recommendation)
// Expected runtime: <5 seconds
// ============================================================
let targetUser = "user@contoso.com";
let alertIP = "203.0.113.50";
// Use the MFA approval time from Query 3 results
let approvalTime = datetime(2026-02-22T14:35:00Z);
// Check from approval time forward to detect ongoing token usage
let postApprovalWindow = 24h;
// --- Part 1: All non-interactive sign-ins post-approval ---
let allNonInteractive = AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (approvalTime .. (approvalTime + postApprovalWindow))
    | where UserPrincipalName == targetUser
    // ResultType is a STRING in this table too (Hasan's gotcha)
    | where ResultType == "0"
    | extend
        DeviceOS = tostring(DeviceDetail.operatingSystem),
        DeviceBrowser = tostring(DeviceDetail.browser),
        LocationCountry = tostring(Location.countryOrRegion),
        LocationCity = tostring(Location.city);
// --- Part 2: Summarize by IP to compare attacker vs legitimate ---
allNonInteractive
| summarize
    TokenRefreshCount = count(),
    FirstTokenRefresh = min(TimeGenerated),
    LastTokenRefresh = max(TimeGenerated),
    DistinctApps = make_set(AppDisplayName, 20),
    DistinctResources = make_set(ResourceDisplayName, 20)
    by UserPrincipalName, IPAddress, DeviceOS, DeviceBrowser, LocationCountry
| extend
    SessionDurationMinutes = datetime_diff("minute", LastTokenRefresh, FirstTokenRefresh),
    IsAttackerIP = iff(IPAddress == alertIP, "YES - ATTACKER IP", "No"),
    // Flag long-running token sessions from the attacker IP
    TokenPersistenceRisk = case(
        IPAddress == alertIP and TokenRefreshCount > 50 and SessionDurationMinutes > 120,
            "CRITICAL - Sustained attacker session (>50 refreshes, >2hr from attacker IP)",
        IPAddress == alertIP and TokenRefreshCount > 20,
            "HIGH - Elevated attacker token activity (>20 refreshes from attacker IP)",
        IPAddress == alertIP and TokenRefreshCount > 0,
            "MEDIUM - Token activity from attacker IP detected",
        IPAddress != alertIP and TokenRefreshCount > 0,
            "INFO - Token activity from non-attacker IP (likely legitimate)",
        "NONE - No non-interactive sign-ins"
    )
| project
    UserPrincipalName,
    IPAddress,
    IsAttackerIP,
    DeviceOS,
    DeviceBrowser,
    LocationCountry,
    TokenRefreshCount,
    FirstTokenRefresh,
    LastTokenRefresh,
    SessionDurationMinutes,
    DistinctApps,
    DistinctResources,
    TokenPersistenceRisk
| order by IsAttackerIP desc, TokenRefreshCount desc
```

### Expected Output Columns

| Column | Type | Description |
|---|---|---|
| UserPrincipalName | string | Target user |
| IPAddress | string | Source IP of token refreshes |
| IsAttackerIP | string | Whether activity is from the attacker IP |
| TokenRefreshCount | long | Number of non-interactive sign-ins |
| FirstTokenRefresh | datetime | First token refresh timestamp |
| LastTokenRefresh | datetime | Last token refresh timestamp |
| SessionDurationMinutes | long | Duration of token session |
| DistinctApps | dynamic | Applications accessed via tokens |
| DistinctResources | dynamic | Resources accessed via tokens |
| TokenPersistenceRisk | string | Risk assessment |

### Performance Notes

- AADNonInteractiveUserSignInLogs is high volume - always filter by UserPrincipalName first
- The summarize pattern aggregates potentially thousands of token refreshes into summary rows per IP
- Expected result: 1-5 rows (one per unique IP/device combination)
- Rows with `IsAttackerIP == "YES"` indicate the attacker is actively using stolen tokens

### Tuning Guidance

- **postApprovalWindow**: Default 24h. Extend to 48-72h if investigating delayed response scenarios
- **TokenRefreshCount thresholds**: Adjust based on organizational norms. Teams and Outlook generate high volumes
- **Token revocation check**: If tokens from the attacker IP are still active after containment actions, immediate token revocation is required via `Revoke-AzureADUserAllRefreshToken`

---

## Query 8: Org-Wide MFA Denial Pattern

**Purpose:** Look across ALL users for MFA denial spikes. If multiple users are being MFA bombed simultaneously, it indicates a coordinated attack campaign, not an isolated incident. This query identifies the scope of the attack by finding all users with elevated MFA denials in the same time window.

**Tables:** SigninLogs

**Investigation Step:** Step 8

### Production Query

```kql
// ============================================================
// Query 8: Org-Wide MFA Denial Pattern
// Purpose: Detect coordinated MFA fatigue campaigns by finding
//          ALL users with elevated MFA denial counts. If
//          multiple users are being MFA bombed simultaneously,
//          this is a coordinated attack, not isolated
// Table: SigninLogs
// Expected runtime: 10-30 seconds (org-wide scan)
// ============================================================
let alertTime = datetime(2026-02-22T14:30:00Z);
let targetUser = "user@contoso.com";
// Window to check for coordinated attacks
let orgWindow = 24h;
// Minimum denial threshold to flag a user
let minDenials = 3;
// --- Part 1: Find all users with MFA denials in the window ---
let mfaDenialsByUser = SigninLogs
    | where TimeGenerated between ((alertTime - orgWindow) .. (alertTime + orgWindow))
    | where ResultType == "500121"
    | summarize
        DenialCount = count(),
        FirstDenial = min(TimeGenerated),
        LastDenial = max(TimeGenerated),
        SourceIPs = make_set(IPAddress, 20),
        SourceCountries = make_set(tostring(Location.countryOrRegion), 10),
        TargetApps = make_set(AppDisplayName, 20),
        MfaMethods = make_set(iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "N/A"), 10),
        DistinctSourceIPs = dcount(IPAddress)
        by UserPrincipalName
    | where DenialCount >= minDenials;
// --- Part 2: Check for shared infrastructure (same attacker IP across users) ---
let sharedIPs = SigninLogs
    | where TimeGenerated between ((alertTime - orgWindow) .. (alertTime + orgWindow))
    | where ResultType == "500121"
    | summarize
        UsersTargeted = dcount(UserPrincipalName),
        TargetUsers = make_set(UserPrincipalName, 50),
        TotalDenials = count()
        by IPAddress
    | where UsersTargeted > 1;
// --- Part 3: Combine user-level and IP-level analysis ---
mfaDenialsByUser
| extend
    IsTargetUser = iff(UserPrincipalName == targetUser, "TARGET USER", "Other victim"),
    BurstDurationMinutes = datetime_diff("minute", LastDenial, FirstDenial),
    // Check if any of this user's denial IPs are shared with other victims
    HasSharedAttackerIP = iff(
        SourceIPs has_any (sharedIPs | project IPAddress),
        "YES - Shared attacker infrastructure detected",
        "No"
    ),
    CampaignAssessment = case(
        // Multiple users targeted from same IP = coordinated campaign
        DistinctSourceIPs == 1 and toscalar(mfaDenialsByUser | count) > 1,
            "COORDINATED CAMPAIGN - Multiple users targeted",
        DenialCount >= 20,
            "AGGRESSIVE ATTACK - 20+ denials against this user",
        DenialCount >= 10,
            "ACTIVE ATTACK - Sustained MFA fatigue attempt",
        DenialCount >= 5,
            "SUSPECTED ATTACK - Elevated denial count",
        DenialCount >= minDenials,
            "POSSIBLE ATTACK - Above threshold",
        "BELOW THRESHOLD"
    )
| project
    UserPrincipalName,
    IsTargetUser,
    DenialCount,
    FirstDenial,
    LastDenial,
    BurstDurationMinutes,
    SourceIPs,
    SourceCountries,
    DistinctSourceIPs,
    TargetApps,
    MfaMethods,
    HasSharedAttackerIP,
    CampaignAssessment
| order by DenialCount desc
```

### Expected Output Columns

| Column | Type | Description |
|---|---|---|
| UserPrincipalName | string | User with MFA denials |
| IsTargetUser | string | "TARGET USER" or "Other victim" |
| DenialCount | long | Total MFA denials for this user |
| FirstDenial / LastDenial | datetime | Denial time range |
| BurstDurationMinutes | long | Duration of denial activity |
| SourceIPs | dynamic | IPs that triggered denials |
| SourceCountries | dynamic | Countries of source IPs |
| DistinctSourceIPs | long | Number of distinct attacker IPs |
| TargetApps | dynamic | Applications targeted |
| HasSharedAttackerIP | string | Whether attacker IP is shared with other victims |
| CampaignAssessment | string | Campaign scope classification |

### Performance Notes

- This query scans 48h of org-wide SigninLogs filtered by ResultType "500121" - moderate to heavy depending on organization size
- The `dcount(UserPrincipalName)` in Part 2 efficiently identifies shared attacker infrastructure
- Expected result: 1 row (isolated attack) or multiple rows (coordinated campaign)
- If multiple users are returned, this should be escalated as a campaign incident, not individual alerts

### Tuning Guidance

- **orgWindow**: Default 24h. For large organizations with many MFA denials, reduce to 6h for faster execution
- **minDenials**: Default 3. Lower to 2 for more sensitive detection but expect false positives from users with Authenticator app issues
- **sharedIPs analysis**: If >3 distinct users are targeted from the same IP, this is almost certainly a coordinated campaign. Cross-reference with threat intelligence
- **Timing correlation**: If multiple users' `FirstDenial` timestamps are within 30 minutes of each other, the attacker is running automated MFA bombing tools

### Datatable Test Query

```kql
// ============================================================
// TEST: Query 8 - Org-Wide MFA Denial Pattern
// Synthetic data: Coordinated MFA fatigue campaign against 3 users
// ============================================================
let testSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    Location: dynamic,
    AppDisplayName: string,
    MfaDetail: dynamic,
    ResultType: string
) [
    // VICTIM 1 (target user): 6 denials from attacker IP
    datetime(2026-02-22T14:30:00Z), "user@contoso.com", "203.0.113.50",
        dynamic({"countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification"}), "500121",
    datetime(2026-02-22T14:30:30Z), "user@contoso.com", "203.0.113.50",
        dynamic({"countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification"}), "500121",
    datetime(2026-02-22T14:31:00Z), "user@contoso.com", "203.0.113.50",
        dynamic({"countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification"}), "500121",
    datetime(2026-02-22T14:31:30Z), "user@contoso.com", "203.0.113.50",
        dynamic({"countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification"}), "500121",
    datetime(2026-02-22T14:32:00Z), "user@contoso.com", "203.0.113.50",
        dynamic({"countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification"}), "500121",
    datetime(2026-02-22T14:32:30Z), "user@contoso.com", "203.0.113.50",
        dynamic({"countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification"}), "500121",
    // VICTIM 2: 4 denials from SAME attacker IP (coordinated campaign)
    datetime(2026-02-22T14:33:00Z), "finance@contoso.com", "203.0.113.50",
        dynamic({"countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification"}), "500121",
    datetime(2026-02-22T14:33:30Z), "finance@contoso.com", "203.0.113.50",
        dynamic({"countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification"}), "500121",
    datetime(2026-02-22T14:34:00Z), "finance@contoso.com", "203.0.113.50",
        dynamic({"countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification"}), "500121",
    datetime(2026-02-22T14:34:30Z), "finance@contoso.com", "203.0.113.50",
        dynamic({"countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification"}), "500121",
    // VICTIM 3: 3 denials from SAME attacker IP
    datetime(2026-02-22T14:35:00Z), "exec@contoso.com", "203.0.113.50",
        dynamic({"countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification"}), "500121",
    datetime(2026-02-22T14:35:30Z), "exec@contoso.com", "203.0.113.50",
        dynamic({"countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification"}), "500121",
    datetime(2026-02-22T14:36:00Z), "exec@contoso.com", "203.0.113.50",
        dynamic({"countryOrRegion":"RU"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification"}), "500121",
    // BENIGN 1: Single MFA denial (below threshold)
    datetime(2026-02-22T10:00:00Z), "normal@contoso.com", "10.0.0.1",
        dynamic({"countryOrRegion":"TR"}), "Microsoft Teams",
        dynamic({"authMethod":"PhoneAppOTP"}), "500121",
    // BENIGN 2: Denial from different IP (not coordinated)
    datetime(2026-02-22T08:00:00Z), "other@contoso.com", "85.100.50.30",
        dynamic({"countryOrRegion":"TR"}), "Microsoft Office 365",
        dynamic({"authMethod":"PhoneAppNotification"}), "500121"
];
// --- Test execution ---
let alertTime = datetime(2026-02-22T14:30:00Z);
let targetUser = "user@contoso.com";
let orgWindow = 24h;
let minDenials = 3;
let mfaDenialsByUser = testSigninLogs
    | where TimeGenerated between ((alertTime - orgWindow) .. (alertTime + orgWindow))
    | where ResultType == "500121"
    | summarize
        DenialCount = count(),
        FirstDenial = min(TimeGenerated),
        LastDenial = max(TimeGenerated),
        SourceIPs = make_set(IPAddress, 20),
        SourceCountries = make_set(tostring(Location.countryOrRegion), 10),
        TargetApps = make_set(AppDisplayName, 20),
        MfaMethods = make_set(iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "N/A"), 10),
        DistinctSourceIPs = dcount(IPAddress)
        by UserPrincipalName
    | where DenialCount >= minDenials;
let sharedIPs = testSigninLogs
    | where TimeGenerated between ((alertTime - orgWindow) .. (alertTime + orgWindow))
    | where ResultType == "500121"
    | summarize
        UsersTargeted = dcount(UserPrincipalName),
        TargetUsers = make_set(UserPrincipalName, 50),
        TotalDenials = count()
        by IPAddress
    | where UsersTargeted > 1;
mfaDenialsByUser
| extend
    IsTargetUser = iff(UserPrincipalName == targetUser, "TARGET USER", "Other victim"),
    BurstDurationMinutes = datetime_diff("minute", LastDenial, FirstDenial),
    CampaignAssessment = case(
        DenialCount >= 20, "AGGRESSIVE ATTACK - 20+ denials against this user",
        DenialCount >= 10, "ACTIVE ATTACK - Sustained MFA fatigue attempt",
        DenialCount >= 5, "SUSPECTED ATTACK - Elevated denial count",
        DenialCount >= minDenials, "POSSIBLE ATTACK - Above threshold",
        "BELOW THRESHOLD"
    )
| project
    UserPrincipalName,
    IsTargetUser,
    DenialCount,
    FirstDenial,
    LastDenial,
    BurstDurationMinutes,
    SourceIPs,
    SourceCountries,
    DistinctSourceIPs,
    TargetApps,
    MfaMethods,
    CampaignAssessment
| order by DenialCount desc
// Expected: 3 rows
//   user@contoso.com: 6 denials, TARGET USER, SUSPECTED ATTACK
//   finance@contoso.com: 4 denials, Other victim, POSSIBLE ATTACK
//   exec@contoso.com: 3 denials, Other victim, POSSIBLE ATTACK
//   All 3 share the same SourceIP (203.0.113.50) = coordinated campaign
//   normal@contoso.com and other@contoso.com filtered out (below threshold)
```

---

## Key KQL Patterns Used

### ResultType "500121" for MFA denial
```kql
// ResultType "500121" means "MFA denied by user" in SigninLogs
// This is the primary signal for MFA fatigue detection
// ResultType is a STRING, not int - compare with quotes
| where ResultType == "500121"     // Correct
// | where ResultType == 500121    // WRONG - will not match
```

### MfaDetail parsing
```kql
// MfaDetail is a dynamic column that can be null when MFA was not performed
// Always guard against null with iff(isnotempty(...))
| extend
    MfaAuthMethod = iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "N/A"),
    MfaAuthDetail = iff(isnotempty(MfaDetail), tostring(MfaDetail.authDetail), "")
```

### AuthenticationDetails array expansion
```kql
// AuthenticationDetails is a dynamic JSON array in SigninLogs
// Each element contains an authentication step
| mv-expand AuthStep = parse_json(AuthenticationDetails)
| extend
    AuthStepMethod = tostring(AuthStep.authenticationMethod),
    AuthStepDetail = tostring(AuthStep.authenticationStepResultDetail),
    AuthStepSuccess = tostring(AuthStep.succeeded)
```

### Time binning for burst detection
```kql
// bin(TimeGenerated, 5m) groups events into 5-minute windows
// Essential for detecting rapid MFA denial bursts
| summarize DenialsIn5Min = count() by UserPrincipalName, bin(TimeGenerated, 5m)
| where DenialsIn5Min >= 3
```

### prev() / next() for sequential event analysis
```kql
// prev() looks at the previous row's value (requires prior order by)
// Used to detect "approval after denial" patterns
| order by TimeGenerated asc
| extend
    PrevResult = prev(MfaResult),
    SecondsSincePrev = datetime_diff("second", TimeGenerated, prev(TimeGenerated))
| where MfaResult == "APPROVED" and PrevResult == "DENIED"
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
| where ResultType == "0"       // Success
| where ResultType == "500121"  // MFA denied
// | where ResultType == 0      // WRONG - will not match
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

### extract() regex for OfficeActivity ClientIP normalization
```kql
// OfficeActivity ClientIP formats vary:
// "1.2.3.4"             - plain IPv4
// "1.2.3.4:12345"       - IPv4 with port
// "[::ffff:1.2.3.4]:80" - IPv6-mapped IPv4 with port
// This regex extracts just the IPv4 address from any format
| extend CleanClientIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)
```

### Self-join for denial-then-approval correlation
```kql
// Use a self-join pattern to correlate denial bursts with subsequent approvals
// Step 1: Aggregate denial bursts
// Step 2: Find approvals in a window after the last denial
// Step 3: Join on UserPrincipalName with time filter
denialBursts
| join kind=inner postDenialApprovals on UserPrincipalName
| where ApprovalTime > LastDenial
| where ApprovalTime < (LastDenial + approvalWindow)
```

## Optimization Notes

1. **Always filter by user + time first** - these are the most selective predicates for single-user investigation
2. **ResultType "500121" is a string** - compare with `"500121"` not `500121`. This is the single most important filter for MFA fatigue detection
3. **IpAddress vs IPAddress** - AADUserRiskEvents uses `IpAddress` (capital A); SigninLogs and AADNonInteractiveUserSignInLogs use `IPAddress` (capital IP). Getting this wrong returns 0 rows with no error
4. **MfaDetail null handling** - always use `iff(isnotempty(MfaDetail), tostring(MfaDetail.authMethod), "N/A")` to avoid empty results when MFA was not attempted
5. **AADNonInteractiveUserSignInLogs is high volume** - always add both user AND IP filter when possible
6. **OfficeActivity ingestion latency** - up to 60 min. Re-run 2 hours after alert for completeness
7. **OfficeActivity ClientIP normalization** - always use `extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)` to handle port numbers and IPv6-mapped formats
8. **prev() requires order by** - the `prev()` window function MUST be preceded by `| order by TimeGenerated asc` to produce correct sequential results
9. **bin() for burst detection** - use `bin(TimeGenerated, 5m)` for rapid burst detection and `bin(TimeGenerated, 1h)` for sustained pattern detection. Never use bin() without a subsequent aggregation
10. **Use `summarize arg_max()` instead of `take 1`** - for deterministic results when selecting a single record per group
11. **Org-wide queries (Query 8) are heavier** - filter by ResultType first to reduce the scan scope before any user-level aggregation
12. **mfaFraud risk event is supplementary** - not all MFA fatigue attacks produce an mfaFraud risk event. Pattern-based detection via ResultType "500121" (Query 2) is the primary method
