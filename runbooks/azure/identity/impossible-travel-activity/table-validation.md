# Table Validation - Impossible Travel Activity (RB-0002)

> **Author:** Hasan (Platform Architect)
> **Reviewed by:** Alp (QA Lead)
> **Version:** 1.0

## Table Schema Validation

### SigninLogs

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 1, 2, 3A, 3B, 4, 7B | Primary timestamp |
| UserPrincipalName | string | All queries | User filter |
| IPAddress | string | Query 1, 2, 3A, 4, 7B | Source IP of sign-in |
| LocationDetails | dynamic | Query 1, 2, 3A, 3B | Contains geoCoordinates.latitude/longitude, city, countryOrRegion, state |
| DeviceDetail | dynamic | Query 1, 4 | Contains deviceId, operatingSystem, browser, isCompliant, isManaged, trustType |
| UserAgent | string | Query 1, 4 | Raw user agent string |
| AppDisplayName | string | Query 1, 3B, 7B | Application accessed |
| ResourceDisplayName | string | Query 1 | Target resource |
| ClientAppUsed | string | Query 1, 4 | Client type |
| AuthenticationRequirement | string | Query 1, 4 | "singleFactorAuthentication" or "multiFactorAuthentication" |
| MfaDetail | dynamic | Query 1, 4 | Contains authMethod, authDetail. Can be null if no MFA |
| ConditionalAccessStatus | string | Query 1, 4 | "success", "failure", "notApplied" |
| ResultType | string | All queries | **STRING not int** - "0" = success |
| CorrelationId | string | Query 1 | Event correlation |
| SessionId | string | Query 1, 4, 5B | Session tracking - critical for token replay detection |

**Gotcha:** `LocationDetails` (with capital D) in SigninLogs vs `Location` in AADUserRiskEvents. Different schema!
**Gotcha:** `LocationDetails.geoCoordinates.latitude` returns a string that must be cast with `toreal()`.
**Gotcha:** `DeviceDetail.deviceId` may be empty for unregistered/BYOD devices.

### AADUserRiskEvents

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 1 | Risk event timestamp |
| UserPrincipalName | string | Query 1 | Affected user |
| RiskEventType | string | Query 1 | Must filter for "impossibleTravel" |
| RiskLevel | string | Query 1 | "low", "medium", "high" |
| DetectionTimingType | string | Query 1 | "realtime" or "offline" |
| IpAddress | string | Query 1 | Capital 'A' - **NOT** IPAddress |
| Location | dynamic | Query 1 | Different schema from SigninLogs LocationDetails |
| AdditionalInfo | dynamic | Query 1 | May contain details about the impossible travel pair |
| CorrelationId | string | Query 1 | Links to SigninLogs |

**Gotcha:** `IpAddress` (capital A) in AADUserRiskEvents vs `IPAddress` (capital IP) in SigninLogs.
**Gotcha:** For impossibleTravel, the IpAddress typically contains the SECOND (anomalous) sign-in IP only.

### AADNonInteractiveUserSignInLogs

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 5A, 5B | Event timestamp |
| UserPrincipalName | string | Query 5A, 5B | User filter |
| IPAddress | string | Query 5A, 5B | Source IP |
| AppDisplayName | string | Query 5A | Application accessed |
| ResourceDisplayName | string | Query 5A | Target resource |
| ResultType | string | Query 5A, 5B | **STRING** - "0" = success |
| OriginalRequestId | string | Query 5A, 5B | Use as session correlation key (SessionId is often empty) |
| LocationDetails | dynamic | Query 5A, 5B | Same schema as SigninLogs |
| IsInteractive | bool | Query 5A | Should be false |

**Gotcha:** This table can have 10-50x the volume of SigninLogs. ALWAYS filter by IP and/or user first.
**Gotcha:** `SessionId` is often empty in this table. Use `OriginalRequestId` instead.
**Gotcha:** Do NOT union raw data from this table with SigninLogs for baseline calculations - summarize separately.

### AuditLogs

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 6A | Event timestamp |
| OperationName | string | Query 6A | Filter by specific operations |
| Category | string | Query 6A | "UserManagement", "ApplicationManagement", etc. |
| InitiatedBy | dynamic | Query 6A | Contains user.userPrincipalName or app.displayName |
| TargetResources | dynamic | Query 6A | Array - must mv-expand |

### OfficeActivity

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 6B, 6C | Event timestamp |
| Operation | string | Query 6B, 6C | Activity type |
| OfficeWorkload | string | Query 6B | "Exchange", "SharePoint", "OneDrive", etc. |
| UserId | string | Query 6B, 6C | UPN format |
| ClientIP | string | Query 6B, 6C | May include port and IPv6-mapped format |
| Parameters | dynamic | Query 6C | Array for inbox rule details |

**Gotcha:** ClientIP can be "198.51.100.42:54321" or "[::ffff:198.51.100.42]:12345". Use `extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)` to normalize.
**Gotcha:** Up to 60 min ingestion latency. Re-run queries 2 hours after alert for complete data.

## Licensing Requirements

| Table | Minimum License | Notes |
|---|---|---|
| SigninLogs | Entra ID Free | Always available |
| AADUserRiskEvents | Entra ID P2 | Required for risk event details |
| AADRiskyUsers | Entra ID P2 | Required for user risk state |
| AADNonInteractiveUserSignInLogs | Entra ID P1+ | Critical for token replay detection |
| AuditLogs | Entra ID Free | Always available |
| IdentityInfo | Sentinel UEBA | Optional, has fallback |
| OfficeActivity | M365 E3+ | Required for blast radius |
| ThreatIntelligenceIndicator | Sentinel + TI feeds | Optional enrichment |
| BehaviorAnalytics | Sentinel UEBA | Optional enrichment |

## geo_distance_2points() Function Reference

```
geo_distance_2points(longitude1, latitude1, longitude2, latitude2)
```

- Returns distance in **meters** (divide by 1000 for km)
- Parameters are in order: **longitude first, then latitude**
- Uses WGS-84 coordinate system (same as GPS)
- Accurate to within ~0.5% for distances up to 20,000 km
