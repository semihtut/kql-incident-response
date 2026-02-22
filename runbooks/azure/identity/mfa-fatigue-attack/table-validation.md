# Table Validation - MFA Fatigue Attack (RB-0005)

> **Author:** Hasan (Platform Architect)
> **Reviewed by:** Alp (QA Lead)
> **Version:** 1.0
> **Date:** 2026-02-22

## Table Schema Validation

### SigninLogs

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | All queries | Primary timestamp - bin() by 5min and 1hr windows for burst detection |
| UserPrincipalName | string | All queries | Target user under MFA fatigue attack |
| ResultType | string | Query 1, 2, 3, 7 | **STRING not int** - "500121" is the GOLDEN indicator for MFA denied by user |
| MfaDetail | dynamic | Query 1, 2 | Contains `authMethod` (e.g., "PhoneAppNotification") and `authDetail` (e.g., "MFA denied; user declined the authentication") |
| AuthenticationRequirement | string | Query 1, 2, 3 | Filter for "multiFactorAuthentication" to scope to MFA-required sign-ins |
| AuthenticationDetails | dynamic | Query 1, 2, 3 | Dynamic ARRAY - contains step-by-step authentication results including MFA step. Use mv-expand to access |
| Status | dynamic | Query 1, 2 | Contains `errorCode` and `additionalDetails` for granular failure context |
| IPAddress | string | Query 1, 2, 3, 4, 5 | Source IP of sign-in - capital 'IP'. Critical for correlating attacker origin |
| LocationDetails | dynamic | Query 2, 3 | Contains geoCoordinates.latitude/longitude, city, countryOrRegion, state |
| UserAgent | string | Query 2, 3 | Browser/client string - attacker tools often have distinctive user agents |
| AppDisplayName | string | Query 2, 3 | Application targeted for MFA bypass |
| DeviceDetail | dynamic | Query 2, 3 | Contains deviceId, operatingSystem, browser, isCompliant, isManaged, trustType |
| ConditionalAccessStatus | string | Query 2, 3 | "success", "failure", "notApplied" - check which CA policies applied during attack |
| CorrelationId | string | Query 1, 2 | Groups related sign-in attempts within the same authentication flow |
| ClientAppUsed | string | Query 2, 3 | Client type - check for legacy auth or unusual clients |

**Gotcha:** `ResultType` is a STRING containing numeric error codes, not an integer. Use `== "500121"` for MFA denied, NOT `== 500121`. This is the single most important filter for MFA fatigue detection.
**Gotcha:** `MfaDetail` is dynamic and can be EMPTY even when MFA was challenged. When MfaDetail is null, fall back to parsing `AuthenticationDetails` to determine MFA outcome. Always implement both paths.
**Gotcha:** `AuthenticationDetails` is a DYNAMIC ARRAY, not a simple dynamic object. You MUST use `mv-expand` to iterate through individual authentication steps. Each element contains `authenticationMethod`, `authenticationStepResultDetail`, `authenticationStepDateTime`, and `succeeded`.
**Gotcha:** Multiple sign-in attempts within the same MFA challenge may share the same `CorrelationId`. Do NOT count CorrelationIds as unique attack attempts - count distinct TimeGenerated + ResultType combinations instead.
**Gotcha:** For MFA fatigue detection, time windowing is critical. Use `bin(TimeGenerated, 5m)` for burst detection (many denials in a short window) and `bin(TimeGenerated, 1h)` for sustained campaign detection. A typical MFA fatigue attack generates 10+ MFA denials (ResultType "500121") within a 10-minute window.

**Key ResultType values for MFA fatigue investigation:**

| ResultType | Meaning | Relevance to MFA Fatigue |
|---|---|---|
| "500121" | Authentication failed during strong authentication request | **PRIMARY INDICATOR** - MFA denied by user. Repeated occurrences = fatigue attack |
| "50074" | Strong authentication required | MFA challenge was sent to user. High volume = bombardment |
| "50076" | MFA required but not satisfied | User did not complete MFA. May indicate ignored push |
| "0" | Success | If preceded by many "500121" entries, indicates user CAPITULATED to fatigue attack |
| "53003" | Blocked by Conditional Access | CA policy blocked the sign-in before MFA could complete |

---

### AADUserRiskEvents

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 4 | Risk event timestamp |
| UserPrincipalName | string | Query 4 | Affected user |
| RiskEventType | string | Query 4 | Filter for "mfaFraud" - Identity Protection's built-in MFA fraud detection |
| RiskLevel | string | Query 4 | "low", "medium", "high" |
| IpAddress | string | Query 4 | Capital 'A' - **NOT** IPAddress. Source IP associated with fraud report |
| Location | dynamic | Query 4 | Contains city and countryOrRegion - different schema from SigninLogs LocationDetails |
| DetectionTimingType | string | Query 4 | "realtime" for mfaFraud detections |
| AdditionalInfo | dynamic | Query 4 | May contain fraud report metadata |
| CorrelationId | string | Query 4 | Links to SigninLogs entry that triggered the fraud report |

**Gotcha:** `IpAddress` (capital A) in AADUserRiskEvents vs `IPAddress` (capital IP) in SigninLogs. Case matters in KQL column references.
**Gotcha:** The "mfaFraud" risk event ONLY fires if the user actively taps "Report Fraud" in the Microsoft Authenticator app. Simply denying or ignoring MFA push notifications does NOT generate this event. This means most MFA fatigue attacks will NOT appear in AADUserRiskEvents at all - they must be detected via SigninLogs ResultType pattern analysis.
**Gotcha:** `Location` field here uses a flat structure with `.city` and `.countryOrRegion`, while SigninLogs uses `LocationDetails` with nested `.geoCoordinates.latitude`/`.longitude`. Do NOT confuse the two schemas.
**Gotcha:** If Identity Protection is not licensed (requires Entra ID P2), this table will be empty. The runbook must still function using SigninLogs-only detection as the primary path.

---

### AADRiskyUsers

| Column | Type | Used In | Notes |
|---|---|---|---|
| UserPrincipalName | string | Query 4 | Affected user |
| RiskLevel | string | Query 4 | Current aggregated risk level |
| RiskState | string | Query 4 | "atRisk", "confirmedCompromised", "remediated", "dismissed" |
| RiskDetail | string | Query 4 | May contain "aiConfirmedSigninSafe" or "adminDismissedAllRiskForUser" |
| RiskLastUpdatedDateTime | datetime | Query 4 | When risk was last updated |

**Gotcha:** This is a STATE table, not an EVENT table. It shows the current aggregated risk state, not individual events. Use `arg_max(TimeGenerated, *)` to get the latest state per user.
**Gotcha:** RiskState may show "remediated" if an admin already took action or if the user self-remediated via password reset.
**Gotcha:** A user under MFA fatigue attack may not yet show elevated risk in this table if the attack is pattern-based (repeated denials) rather than fraud-reported. Cross-reference with AADUserRiskEvents for "mfaFraud" events and with SigninLogs for ResultType "500121" patterns.

---

### AADNonInteractiveUserSignInLogs

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 5 | Event timestamp |
| UserPrincipalName | string | Query 5 | User filter |
| IPAddress | string | Query 5 | Source IP |
| AppDisplayName | string | Query 5 | Application accessed |
| ResourceDisplayName | string | Query 5 | Target resource |
| ResultType | string | Query 5 | **STRING** - "0" = success |
| OriginalRequestId | string | Query 5 | Use as session correlation key (SessionId is often empty) |
| LocationDetails | dynamic | Query 5 | Same schema as SigninLogs |

**Gotcha:** `SessionId` is often empty in this table. Use `OriginalRequestId` instead for session correlation.
**Gotcha:** This table can have 10-50x the volume of SigninLogs. Token refreshes generate a row each time. ALWAYS filter by IP and/or user first, then apply time range.
**Gotcha:** After an MFA fatigue attack succeeds (user capitulates), check this table for token refresh activity from the attacker's IP. Non-interactive sign-ins from the same IP confirm the attacker obtained a valid session and is actively using it.
**Gotcha:** Do NOT union raw data from this table with SigninLogs for baseline calculations - summarize each table separately, then combine results.

---

### AuditLogs

| Column | Type | Used In | Notes |
|---|---|---|---|
| TimeGenerated | datetime | Query 6 | Event timestamp |
| OperationName | string | Query 6 | Filter by specific operations |
| Category | string | Query 6 | "UserManagement", "ApplicationManagement", etc. |
| InitiatedBy | dynamic | Query 6 | Contains user.userPrincipalName or app.displayName |
| TargetResources | dynamic | Query 6 | Array - must use mv-expand to access elements |

**Gotcha:** `InitiatedBy` is dynamic with two possible structures: `InitiatedBy.user.userPrincipalName` (for user-initiated) or `InitiatedBy.app.displayName` (for app-initiated). Always check both.
**Gotcha:** `TargetResources` is a dynamic ARRAY - use `mv-expand` or `TargetResources[0]` to access elements. `TargetResources[0].modifiedProperties` contains oldValue and newValue for changes.

**Key OperationName values for post-MFA-fatigue persistence detection:**

| OperationName | Category | Security Relevance |
|---|---|---|
| Register security info | UserManagement | Attacker registering their own MFA method after gaining access |
| User registered security info | UserManagement | MFA method registration - highest priority post-compromise action |
| User deleted security info | UserManagement | Attacker removing victim's MFA methods to maintain control |
| Consent to application | ApplicationManagement | OAuth app consent for persistent access (survives password reset) |
| Add app role assignment to service principal | ApplicationManagement | API permission grant for data exfiltration |
| Add owner to application | ApplicationManagement | App ownership change for long-term persistence |
| Update application | ApplicationManagement | Adding credentials/certificates to application |
| Add member to role | RoleManagement | Privilege escalation after MFA bypass |

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
**Gotcha:** Up to 60 min ingestion latency. Re-run queries 2 hours after alert time for complete data. When checking post-MFA-fatigue activity, use a 4-hour window from the successful sign-in time, not 1 hour.
**Gotcha:** After MFA fatigue success, check for high-impact operations: inbox rule creation (email forwarding for BEC), mass file downloads (data exfiltration), and SharePoint sharing changes (external sharing). These are the most common attacker actions after bypassing MFA via fatigue.

---

## Critical Gotchas - Summary

These are the most impactful schema issues that Samet must handle correctly. Getting any of these wrong will produce silent failures or incorrect results.

### 1. ResultType "500121" Is the Core Detection Signal (CRITICAL)

ResultType "500121" means "Authentication failed during strong authentication request" - this is the user DENYING the MFA push notification. A burst of "500121" entries followed by ResultType "0" (success) from the same IP is the textbook MFA fatigue attack pattern. ResultType is a STRING - always use string comparison operators.

### 2. MfaDetail Can Be Empty Even When MFA Was Challenged (HIGH IMPACT)

The `MfaDetail` column is frequently null or empty, even on sign-in attempts where MFA was actively challenged. This is a known inconsistency. Samet must always implement a fallback path using `AuthenticationDetails` (mv-expand the array, then check `authenticationStepResultDetail` for MFA-related values). Never rely solely on MfaDetail.

### 3. AuthenticationDetails Requires mv-expand (HIGH IMPACT)

`AuthenticationDetails` is a dynamic ARRAY, not a flat object. Writing `AuthenticationDetails.authenticationMethod` will return null. You must use:
```
mv-expand AuthStep = AuthenticationDetails
| where AuthStep.authenticationMethod == "PhoneAppNotification"
```

### 4. IP Address Column Name Inconsistency (HIGH IMPACT)

| Table | Column Name | Casing |
|---|---|---|
| SigninLogs | `IPAddress` | Capital I, capital P |
| AADNonInteractiveUserSignInLogs | `IPAddress` | Capital I, capital P |
| AADUserRiskEvents | `IpAddress` | Capital I, lowercase p |
| OfficeActivity | `ClientIP` | Completely different name + includes port |

**Recommendation:** Create a `let cleanIP = ...` function at the top of queries that normalizes all IP formats. For OfficeActivity, always use `extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)`.

### 5. CorrelationId Does Not Equal Unique Attack Attempt (MEDIUM IMPACT)

Multiple sign-in log entries can share the same `CorrelationId` when they are part of the same authentication flow. For MFA fatigue counting, count distinct `TimeGenerated` + `ResultType` combinations, or count rows directly. Do not use `dcount(CorrelationId)` as the attack attempt counter.

### 6. "mfaFraud" Risk Event Is Unreliable for Detection (MEDIUM IMPACT)

The "mfaFraud" risk event in AADUserRiskEvents only fires when the user actively taps "Report Fraud" in the Authenticator app. Most users simply deny the push or let it expire. This means the primary detection path MUST be SigninLogs ResultType pattern analysis, not AADUserRiskEvents. Treat the mfaFraud event as a high-confidence supplementary signal, not the primary detection.

### 7. Time Windowing for Burst Detection (MEDIUM IMPACT)

MFA fatigue attacks are defined by temporal patterns. Use `bin(TimeGenerated, 5m)` for short burst detection and `bin(TimeGenerated, 1h)` for sustained campaign detection. A typical threshold is 5+ MFA denials within 10 minutes from the same IP targeting the same user. Without proper time binning, individual MFA denials look like normal failed sign-ins.

### 8. AADNonInteractiveUserSignInLogs Volume (PERFORMANCE)

This table can contain 10-50x more rows than SigninLogs. Never query this table without tight user and/or IP filters. For baseline calculations, summarize separately from SigninLogs - do not union raw data.

---

## Licensing Requirements

| Table | Minimum License | Notes |
|---|---|---|
| SigninLogs | Entra ID Free | **PRIMARY TABLE** - Always available. Contains all MFA challenge/deny/approve data |
| AADUserRiskEvents | Entra ID P2 | Optional - only captures "mfaFraud" if user reports fraud via Authenticator app |
| AADRiskyUsers | Entra ID P2 | Optional - shows aggregated user risk state |
| AADNonInteractiveUserSignInLogs | Entra ID P1+ | Needed to detect post-compromise token usage from attacker IP |
| AuditLogs | Entra ID Free | Always available - critical for detecting persistence actions post-MFA bypass |
| OfficeActivity | M365 E3+ | Required for blast radius assessment (email forwarding, file exfiltration) |

### Licensing Tiers and Investigation Impact

| License Tier | Tables Available | Investigation Impact |
|---|---|---|
| **Entra ID Free + Sentinel** | SigninLogs, AuditLogs | Core MFA fatigue detection via ResultType "500121" pattern analysis. Can detect attack and check post-compromise persistence. **This is a viable minimum** unlike other runbooks because SigninLogs is the primary detection source. |
| **Entra ID P2 + Sentinel** | Above + AADUserRiskEvents, AADRiskyUsers, AADNonInteractiveUserSignInLogs | Adds mfaFraud risk event correlation, user risk state, and token tracking from attacker IP. Baseline comparison with non-interactive logs. |
| **Entra ID P2 + M365 E3 + Sentinel** | Above + OfficeActivity | Full investigation including post-compromise email/file activity and blast radius assessment. |

**Minimum recommended:** Entra ID Free + Sentinel (SigninLogs alone is sufficient for core MFA fatigue detection)
**Optimal:** Entra ID P2 + M365 E5 + Sentinel for full investigation depth including risk events, token tracking, and blast radius

---

## Key Schema Differences from RB-0001/RB-0002/RB-0003/RB-0004

1. **SigninLogs is the PRIMARY table, not AADUserRiskEvents** - Unlike all previous runbooks where AADUserRiskEvents was the starting point, MFA fatigue detection is fundamentally a SigninLogs pattern analysis problem. The "mfaFraud" risk event in AADUserRiskEvents is unreliable because it requires user-initiated fraud reporting. Samet must build the core detection logic in SigninLogs using ResultType "500121" burst patterns.
2. **No ThreatIntelligenceIndicator needed** - Unlike anonymousIPAddress (RB-0004) which benefits from TI feed enrichment to confirm anonymizer service type, MFA fatigue is a behavioral detection. The attack is identified by the temporal pattern of MFA denials, not by IP reputation. TI enrichment adds no value to this specific detection.
3. **Time-based pattern analysis is the core technique** - Unlike previous runbooks that primarily filter on specific risk event types or geographic calculations, this runbook requires temporal aggregation using `bin()`, `count()`, and sliding window analysis. The detection signal is "many MFA denials in a short period followed by an approval."
4. **Baseline comparison focuses on MFA prompt frequency** - The mandatory baseline query (per project rules) must compare the user's normal MFA challenge rate against the attack period. A user who normally sees 2-3 MFA challenges per day suddenly receiving 15+ in 10 minutes is the anomaly signal.
5. **Lower licensing floor** - This is the first runbook where the core detection works with Entra ID Free + Sentinel (SigninLogs only). Previous runbooks required Entra ID P2 for AADUserRiskEvents as the primary detection source. This makes MFA fatigue detection accessible to organizations without P2 licensing.

---

**Validation complete. All 6 tables confirmed valid. No ThreatIntelligenceIndicator table needed for this behavioral detection. I need Samet to write the queries with special attention to ResultType "500121" burst pattern detection using bin() time windows, and to implement dual-path MFA detail extraction (MfaDetail with AuthenticationDetails fallback).**
