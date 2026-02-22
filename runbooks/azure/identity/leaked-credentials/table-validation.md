# Table Validation - Leaked Credentials (RB-0003)

> **Author:** Hasan (Platform Architect)
> **Reviewed by:** Alp (QA Lead)
> **Version:** 1.0

## Table Schema Validation

### AADUserRiskEvents

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 1 | Risk event timestamp (offline - may lag actual leak by hours/days) |
| UserPrincipalName | string | Query 1 | Affected user |
| RiskEventType | string | Query 1 | Must filter for "leakedCredentials" |
| RiskLevel | string | Query 1 | "low", "medium", "high" |
| RiskDetail | string | Query 1 | May contain "aiConfirmedSigninSafe" or "adminDismissedAllRiskForUser" |
| RiskState | string | Query 1 | "atRisk", "confirmedCompromised", "remediated", "dismissed" |
| DetectionTimingType | string | Query 1 | Always "offline" for leakedCredentials |
| IpAddress | string | Query 1 | Usually EMPTY for leakedCredentials (no associated sign-in) |
| Location | dynamic | Query 1 | Usually EMPTY for leakedCredentials |
| AdditionalInfo | dynamic | Query 1 | May contain leak source metadata |
| CorrelationId | string | Query 1 | Links to related events |

**Gotcha:** For leakedCredentials, IpAddress and Location are typically empty because the detection comes from credential database matching, not a sign-in event.
**Gotcha:** DetectionTimingType is always "offline" - there is processing lag between credential acquisition and matching.
**Gotcha:** `IpAddress` (capital A) in AADUserRiskEvents vs `IPAddress` (capital IP) in SigninLogs.

### AADRiskyUsers

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 2 | Last update timestamp |
| UserPrincipalName | string | Query 2 | Affected user |
| UserDisplayName | string | Query 2 | Display name |
| RiskLevel | string | Query 2 | Current risk level |
| RiskState | string | Query 2 | Current risk state |
| RiskDetail | string | Query 2 | Risk detail reason |
| RiskLastUpdatedDateTime | datetime | Query 2 | When risk was last updated |
| IsProcessing | bool | Query 2 | Whether risk is still being evaluated |

**Gotcha:** RiskState may show "remediated" if an admin already took action or if password was already reset.

### SigninLogs

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 3, 4A, 4B, 7B | Primary timestamp |
| UserPrincipalName | string | All queries | User filter |
| IPAddress | string | Query 3, 4A, 4B, 7B | Source IP of sign-in |
| LocationDetails | dynamic | Query 3, 4A, 4B | Contains geoCoordinates, city, countryOrRegion, state |
| DeviceDetail | dynamic | Query 4A | Contains deviceId, operatingSystem, browser, isCompliant, isManaged |
| UserAgent | string | Query 4A | Raw user agent string |
| AppDisplayName | string | Query 3, 4A, 7B | Application accessed |
| ResourceDisplayName | string | Query 4A | Target resource |
| ClientAppUsed | string | Query 4A | Client type - CRITICAL for legacy auth detection |
| AuthenticationRequirement | string | Query 4A | "singleFactorAuthentication" or "multiFactorAuthentication" |
| MfaDetail | dynamic | Query 4A | Contains authMethod, authDetail. Can be null |
| ConditionalAccessStatus | string | Query 4A | "success", "failure", "notApplied" |
| ResultType | string | All queries | **STRING not int** - "0" = success |
| RiskLevelDuringSignIn | string | Query 4A | Risk at sign-in time |
| RiskLevelAggregated | string | Query 4A | Aggregated risk level |
| IsInteractive | bool | Query 3 | Should be true for SigninLogs |

**Gotcha:** `ClientAppUsed` values "Exchange ActiveSync", "IMAP4", "POP3", "SMTP", "Other clients" indicate legacy authentication that bypasses MFA.
**Gotcha:** `ResultType` is a STRING. Common codes: "0" (success), "50126" (bad password), "50074" (MFA required), "53003" (blocked by CA).
**Gotcha:** For leaked credentials investigation, we need BOTH successful AND failed sign-ins. Failed sign-ins show credential testing attempts.

### AuditLogs

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 2, 5A | Event timestamp |
| OperationName | string | Query 2, 5A | Filter by specific operations |
| Category | string | Query 2, 5A | "UserManagement", "ApplicationManagement", etc. |
| InitiatedBy | dynamic | Query 2, 5A | Contains user.userPrincipalName or app.displayName |
| TargetResources | dynamic | Query 2, 5A | Array - must mv-expand |

**Gotcha:** Password change operations: "Change user password" (self-service), "Reset user password" (admin), "Reset password (by admin)".

### AADNonInteractiveUserSignInLogs

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 4B | Event timestamp |
| UserPrincipalName | string | Query 4B | User filter |
| IPAddress | string | Query 4B | Source IP |
| AppDisplayName | string | Query 4B | Application accessed |
| ResourceDisplayName | string | Query 4B | Target resource |
| ResultType | string | Query 4B | **STRING** - "0" = success |
| OriginalRequestId | string | Query 4B | Use as session correlation key |
| LocationDetails | dynamic | Query 4B | Same schema as SigninLogs |

**Gotcha:** This table can have 10-50x the volume of SigninLogs. ALWAYS filter by user first.
**Gotcha:** `SessionId` is often empty in this table. Use `OriginalRequestId` instead.

### OfficeActivity

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 5B, 5C | Event timestamp |
| Operation | string | Query 5B, 5C | Activity type |
| OfficeWorkload | string | Query 5B | "Exchange", "SharePoint", "OneDrive", etc. |
| UserId | string | Query 5B, 5C | UPN format |
| ClientIP | string | Query 5B, 5C | May include port and IPv6-mapped format |
| Parameters | dynamic | Query 5C | Array for inbox rule details |

**Gotcha:** ClientIP can be "198.51.100.42:54321" or "[::ffff:198.51.100.42]:12345". Use `extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)` to normalize.
**Gotcha:** Up to 60 min ingestion latency. Re-run queries 2 hours after alert for complete data.

### ThreatIntelligenceIndicator

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 7A | Indicator timestamp |
| NetworkIP | string | Query 7A | IP indicator |
| Active | bool | Query 7A | Must be true |
| ExpirationDateTime | datetime | Query 7A | Must be in the future |
| ConfidenceScore | int | Query 7A | Filter >= 50 |
| ThreatType | string | Query 7A | Type of threat |
| Description | string | Query 7A | Description text |
| ThreatSeverity | string | Query 7A | Severity level |

## Licensing Requirements

| Table | Minimum License | Notes |
|---|---|---|
| AADUserRiskEvents | Entra ID P2 | Required for leaked credential risk event |
| AADRiskyUsers | Entra ID P2 | Required for user risk state |
| SigninLogs | Entra ID Free | Always available |
| AADNonInteractiveUserSignInLogs | Entra ID P1+ | Needed for token/session analysis |
| AuditLogs | Entra ID Free | Always available |
| OfficeActivity | M365 E3+ | Required for blast radius |
| ThreatIntelligenceIndicator | Sentinel + TI feeds | Optional enrichment |

## Key Schema Differences from RB-0001/RB-0002

1. **No IP/Location in risk event** - Unlike impossibleTravel or unfamiliarFeatures, leakedCredentials risk events typically have empty IpAddress and Location fields
2. **ResultType filtering changes** - In this runbook we intentionally include BOTH successful ("0") and failed sign-ins to detect credential testing
3. **ClientAppUsed becomes critical** - Legacy auth detection is a key investigation vector since leaked passwords bypass MFA through legacy protocols
4. **Password change detection via AuditLogs** - Must check OperationName for password-related operations to determine if credential is still valid
