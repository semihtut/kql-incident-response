# Table Validation - Anonymous IP Address Sign-In (RB-0004)

> **Author:** Hasan (Platform Architect)
> **Reviewed by:** Alp (QA Lead)
> **Version:** 1.0
> **Date:** 2026-02-22

## Table Schema Validation

### AADUserRiskEvents

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 1 | Risk event timestamp |
| UserPrincipalName | string | Query 1 | Affected user |
| RiskEventType | string | Query 1 | Must filter for "anonymizedIPAddress" |
| RiskLevel | string | Query 1 | "low", "medium", "high" |
| IpAddress | string | Query 1 | Capital 'A' - **NOT** IPAddress. AVAILABLE for this alert (unlike leakedCredentials) |
| Location | dynamic | Query 1 | Contains city and countryOrRegion - different schema from SigninLogs LocationDetails |
| DetectionTimingType | string | Query 1 | "realtime" for anonymous IP detections |
| AdditionalInfo | dynamic | Query 1 | May contain anonymizer service metadata |
| CorrelationId | string | Query 1 | Links to SigninLogs entry that triggered this risk event |

**Gotcha:** `IpAddress` (capital A) in AADUserRiskEvents vs `IPAddress` (capital IP) in SigninLogs. Case matters in KQL column references.
**Gotcha:** Unlike leakedCredentials (RB-0003), the IpAddress field IS populated for anonymizedIPAddress detections because the risk event is tied to an actual sign-in from a known anonymizer IP.
**Gotcha:** `Location` field here uses a flat structure with `.city` and `.countryOrRegion`, while SigninLogs uses `LocationDetails` with nested `.geoCoordinates.latitude`/`.longitude`. Do NOT confuse the two schemas.
**Gotcha:** DetectionTimingType is typically "realtime" for anonymizedIPAddress because the detection occurs during the sign-in event, not via offline batch processing.

---

### SigninLogs

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 2, 3, 4, 7B | Primary timestamp |
| UserPrincipalName | string | All queries | User filter |
| IPAddress | string | Query 2, 3, 4, 7B | Source IP of sign-in - capital 'IP' |
| LocationDetails | dynamic | Query 2, 3, 4 | Contains geoCoordinates.latitude/longitude, city, countryOrRegion, state |
| DeviceDetail | dynamic | Query 2, 4 | Contains deviceId, operatingSystem, browser, isCompliant, isManaged, trustType |
| AppDisplayName | string | Query 2, 3, 7B | Application accessed |
| AuthenticationRequirement | string | Query 2, 4 | "singleFactorAuthentication" or "multiFactorAuthentication" |
| MfaDetail | dynamic | Query 2, 4 | Contains authMethod, authDetail. Can be null if no MFA performed |
| ClientAppUsed | string | Query 2, 4 | Client type - check for legacy auth protocols |
| ConditionalAccessStatus | string | Query 2, 4 | "success", "failure", "notApplied" |
| ResultType | string | All queries | **STRING not int** - "0" = success |

**Gotcha:** `ResultType` is a STRING containing numeric error codes, not an integer. Use `== "0"` for success, NOT `== 0`. Common codes: "0" (success), "50126" (bad password), "50074" (MFA required), "53003" (blocked by Conditional Access).
**Gotcha:** `LocationDetails` (with capital D) in SigninLogs vs `Location` in AADUserRiskEvents. Different column names AND different schemas.
**Gotcha:** `MfaDetail` is dynamic and can be EMPTY if MFA was not performed. Always check with `isnotempty(MfaDetail)` before accessing nested fields.
**Gotcha:** For anonymous IP investigations, include BOTH successful AND failed sign-ins. A failed sign-in from an anonymizer IP is still a significant indicator of credential testing.

---

### AADRiskyUsers

| Column | Type | Used In | Notes |
|---|---|---|---|
| UserPrincipalName | string | Query 2 | Affected user |
| RiskLevel | string | Query 2 | Current aggregated risk level |
| RiskState | string | Query 2 | "atRisk", "confirmedCompromised", "remediated", "dismissed" |
| RiskDetail | string | Query 2 | May contain "aiConfirmedSigninSafe" or "adminDismissedAllRiskForUser" |
| RiskLastUpdatedDateTime | datetime | Query 2 | When risk was last updated |

**Gotcha:** This is a STATE table, not an EVENT table. It shows the current aggregated risk state, not individual events. Use `arg_max(TimeGenerated, *)` to get the latest state per user.
**Gotcha:** RiskState may show "remediated" if an admin already took action or if the user self-remediated via password reset.
**Gotcha:** A single user can have multiple risk events (e.g., anonymizedIPAddress + unfamiliarFeatures). AADRiskyUsers shows the AGGREGATED risk, not per-event risk. Cross-reference with AADUserRiskEvents for event-level detail.

---

### AADNonInteractiveUserSignInLogs

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 4 | Event timestamp |
| UserPrincipalName | string | Query 4 | User filter |
| IPAddress | string | Query 4 | Source IP |
| AppDisplayName | string | Query 4 | Application accessed |
| ResourceDisplayName | string | Query 4 | Target resource |
| ResultType | string | Query 4 | **STRING** - "0" = success |
| OriginalRequestId | string | Query 4 | Use as session correlation key (SessionId is often empty) |
| LocationDetails | dynamic | Query 4 | Same schema as SigninLogs |

**Gotcha:** `SessionId` is often empty in this table. Use `OriginalRequestId` instead for session correlation.
**Gotcha:** This table can have 10-50x the volume of SigninLogs. Token refreshes generate a row each time. ALWAYS filter by IP and/or user first, then apply time range.
**Gotcha:** For anonymous IP investigations, check whether token refresh requests continue from the same anonymizer IP after the initial sign-in. This indicates persistent VPN/Tor usage (possibly legitimate) vs a one-time anonymized credential test.
**Gotcha:** Do NOT union raw data from this table with SigninLogs for baseline calculations - summarize each table separately, then combine results.

---

### AuditLogs

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 5 | Event timestamp |
| OperationName | string | Query 5 | Filter by specific operations |
| Category | string | Query 5 | "UserManagement", "ApplicationManagement", etc. |
| InitiatedBy | dynamic | Query 5 | Contains user.userPrincipalName or app.displayName |
| TargetResources | dynamic | Query 5 | Array - must use mv-expand to access elements |

**Gotcha:** `InitiatedBy` is dynamic with two possible structures: `InitiatedBy.user.userPrincipalName` (for user-initiated) or `InitiatedBy.app.displayName` (for app-initiated). Always check both.
**Gotcha:** `TargetResources` is a dynamic ARRAY - use `mv-expand` or `TargetResources[0]` to access elements. `TargetResources[0].modifiedProperties` contains oldValue and newValue for changes.

**Key OperationName values for persistence detection after anonymous IP sign-in:**

| OperationName | Category | Security Relevance |
|---|---|---|
| Register security info | UserManagement | MFA method registration from anonymizer IP |
| User registered security info | UserManagement | MFA registration event |
| User deleted security info | UserManagement | MFA method removal (attacker covering tracks) |
| Consent to application | ApplicationManagement | OAuth app consent (persistence) |
| Add app role assignment to service principal | ApplicationManagement | API permission grant |
| Add owner to application | ApplicationManagement | App ownership change (persistence) |
| Update application | ApplicationManagement | App credential/certificate changes |

---

### OfficeActivity

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 6 | Event timestamp |
| UserId | string | Query 6 | UPN format - matches SigninLogs.UserPrincipalName directly |
| Operation | string | Query 6 | Activity type |
| ClientIP | string | Query 6 | Needs regex extraction for clean IP |
| OfficeWorkload | string | Query 6 | "Exchange", "SharePoint", "OneDrive", etc. |
| Parameters | dynamic | Query 6 | Array for inbox rule details |

**Gotcha:** `ClientIP` can be in multiple formats: "198.51.100.42", "198.51.100.42:54321" (with port), or "[::ffff:198.51.100.42]:12345" (IPv6-mapped with port). Use `extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)` to normalize to a clean IPv4 address before joining with other tables.
**Gotcha:** Up to 60 min ingestion latency. Re-run queries 2 hours after alert time for complete data. When checking post-sign-in activity, use a 4-hour window from the sign-in time, not 1 hour.
**Gotcha:** For anonymous IP investigations, compare the extracted ClientIP against the anonymizer IP from the sign-in. If OfficeActivity shows the SAME anonymizer IP, the attacker is actively operating from that session. If OfficeActivity shows a DIFFERENT IP, the user may have separate legitimate sessions overlapping.

---

### ThreatIntelligenceIndicator

| Column | Type | Used In | Notes |
|---|---|---|---|
| NetworkIP | string | Query 7A | IP indicator to match against sign-in IP |
| ThreatType | string | Query 7A | Type of threat (e.g., "Anonymizer", "Proxy", "TOR") |
| ConfidenceScore | int | Query 7A | Filter >= 50 to reduce noise |
| Active | bool | Query 7A | Must be true |
| ExpirationDateTime | datetime | Query 7A | Must be in the future (`> now()`) |
| Description | string | Query 7A | Description text |
| ThreatSeverity | string | Query 7A | Severity level |

**Gotcha:** ALWAYS filter for active indicators: `where Active == true` and `where ExpirationDateTime > now()`.
**Gotcha:** NetworkIP may contain IPv4 or IPv6. Match format with the IP from SigninLogs.
**Gotcha:** If no TI feeds are configured, this table will be EMPTY. This is common in smaller environments. Document as an optional enrichment step, not a required one.
**Gotcha:** For anonymous IP investigations, ThreatType values of "Anonymizer", "Proxy", or "TOR" are especially relevant and confirm the nature of the anonymizer service detected by Identity Protection.

---

## Critical Gotchas - Summary

These are the most impactful schema issues that Samet must handle correctly. Getting any of these wrong will produce silent failures or incorrect results.

### 1. IP Address Column Name Inconsistency (HIGH IMPACT)

| Table | Column Name | Casing |
|---|---|---|
| SigninLogs | `IPAddress` | Capital I, capital P |
| AADNonInteractiveUserSignInLogs | `IPAddress` | Capital I, capital P |
| AADUserRiskEvents | `IpAddress` | Capital I, lowercase p |
| OfficeActivity | `ClientIP` | Completely different name + includes port |
| ThreatIntelligenceIndicator | `NetworkIP` | Completely different name |

**Recommendation:** Create a `let cleanIP = ...` function at the top of queries that normalizes all IP formats. For OfficeActivity, always use `extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)`.

### 2. ResultType Is a STRING, Not an Integer (HIGH IMPACT)

`ResultType` in both SigninLogs and AADNonInteractiveUserSignInLogs is a **string**. Writing `where ResultType == 0` will silently return zero results. Always use `where ResultType == "0"`.

### 3. Location Schema Mismatch Between Tables (MEDIUM IMPACT)

| Table | Column | Schema |
|---|---|---|
| SigninLogs | `LocationDetails` | Dynamic with `.geoCoordinates.latitude`, `.geoCoordinates.longitude`, `.city`, `.countryOrRegion`, `.state` |
| AADUserRiskEvents | `Location` | Dynamic with `.city`, `.countryOrRegion` (flatter structure, no geoCoordinates) |

These are NOT interchangeable. Do not copy column references from one table schema to another.

### 4. SessionId vs OriginalRequestId (MEDIUM IMPACT)

In AADNonInteractiveUserSignInLogs, `SessionId` is frequently empty. Use `OriginalRequestId` for session correlation instead. This does NOT apply to SigninLogs where SessionId is generally populated.

### 5. OfficeActivity ClientIP Format (MEDIUM IMPACT)

ClientIP includes port numbers and IPv6-mapped formats. Raw values cannot be joined directly with SigninLogs.IPAddress. Always extract the IPv4 address first.

### 6. AADNonInteractiveUserSignInLogs Volume (PERFORMANCE)

This table can contain 10-50x more rows than SigninLogs. Never query this table without tight user and/or IP filters. For baseline calculations, summarize separately from SigninLogs - do not union raw data.

---

## Licensing Requirements

| Table | Minimum License | Notes |
|---|---|---|
| AADUserRiskEvents | Entra ID P2 | Required - this is the primary source for the anonymizedIPAddress risk event |
| SigninLogs | Entra ID Free | Always available |
| AADRiskyUsers | Entra ID P2 | Required for user risk state |
| AADNonInteractiveUserSignInLogs | Entra ID P1+ | Needed for token/session analysis from anonymizer IPs |
| AuditLogs | Entra ID Free | Always available |
| OfficeActivity | M365 E3+ | Required for post-sign-in activity and blast radius |
| ThreatIntelligenceIndicator | Sentinel + TI feeds | Optional enrichment - confirms anonymizer service classification |

### Licensing Tiers and Investigation Impact

| License Tier | Tables Available | Investigation Impact |
|---|---|---|
| **Entra ID Free + Sentinel** | SigninLogs, AuditLogs, ThreatIntelligenceIndicator | Can check sign-in details and TI enrichment only. No risk event details. No non-interactive log analysis. Severely limited investigation. |
| **Entra ID P2 + Sentinel** | Above + AADUserRiskEvents, AADRiskyUsers, AADNonInteractiveUserSignInLogs | Full risk event analysis. Token tracking from anonymizer IPs. Baseline comparison. Core investigation complete. |
| **Entra ID P2 + M365 E3 + Sentinel** | Above + OfficeActivity | Full investigation including post-sign-in email/file activity and blast radius assessment. |
| **Entra ID P2 + M365 E3 + Sentinel + TI Feeds** | All 7 tables | Full investigation with IP reputation enrichment confirming anonymizer service type. |

**Minimum recommended:** Entra ID P2 + M365 E3 + Sentinel
**Optimal:** Entra ID P2 + M365 E5 + Sentinel with TI feeds configured

---

## Key Schema Differences from RB-0001/RB-0002/RB-0003

1. **IpAddress IS populated in risk event** - Unlike leakedCredentials (RB-0003) where IpAddress is typically empty, the anonymizedIPAddress risk event always has the offending IP because the detection is triggered by a sign-in from a known anonymizer
2. **DetectionTimingType is realtime** - Unlike leakedCredentials (always offline) and some impossibleTravel detections (can be offline), anonymizedIPAddress is detected in realtime during the sign-in event
3. **TI enrichment is especially relevant** - The ThreatIntelligenceIndicator table provides direct confirmation of the anonymizer service type (Tor, VPN, proxy), which is critical for distinguishing legitimate privacy-conscious users from threat actors
4. **No geo_distance calculation needed** - Unlike impossibleTravel (RB-0002), this runbook does not require geographic distance calculations. The investigation focuses on IP reputation and anonymizer classification rather than physical location logic

---

**Validation complete. All 7 tables confirmed valid. I need Samet to write the queries based on Arina's investigation flow and my table/column guidance.**
