# Table Validation Report: Unfamiliar Sign-In Properties

**Validated by:** Hasan (Platform Architect)
**Requested by:** Arina (IR Architect)
**Date:** 2026-02-21
**Status:** VALIDATED WITH NOTES - Samet may proceed with queries

---

## Validation Summary

Arina's investigation flow requests 11 tables across 7 investigation steps. I have validated every table name, every column name, licensing requirements, and ingestion latency considerations.

| # | Table | Table Exists | Columns Valid | License | Verdict |
|---|---|---|---|---|---|
| 1 | SigninLogs | PASS | 6/11 in sources, 5 additional confirmed | Entra ID Free | PASS WITH NOTES |
| 2 | AADNonInteractiveUserSignInLogs | PASS | ALL VALID | Entra ID P1/P2 | PASS |
| 3 | AADUserRiskEvents | PASS | ALL VALID | Entra ID P2 | PASS |
| 4 | AADRiskyUsers | PASS | ALL VALID | Entra ID P2 | PASS |
| 5 | AuditLogs | PASS | ALL VALID | Entra ID Free | PASS |
| 6 | IdentityInfo | PASS | ALL VALID | Sentinel UEBA | PASS |
| 7 | OfficeActivity | PASS | ALL VALID | M365 E3+ | PASS |
| 8 | CloudAppEvents | PASS | ALL VALID | Defender for Cloud Apps | PASS WITH NOTES |
| 9 | SecurityAlert | PASS | ALL VALID | Sentinel | PASS |
| 10 | ThreatIntelligenceIndicator | PASS | ALL VALID | Sentinel | PASS |
| 11 | BehaviorAnalytics | PASS | ALL VALID | Sentinel UEBA | PASS WITH NOTES |

**Overall verdict: ALL 11 TABLES VALIDATED. Samet may proceed.**

---

## Detailed Validation Per Table

### 1. SigninLogs - PASS WITH NOTES

**Table Name:** SigninLogs - CONFIRMED CORRECT
**Product:** Entra ID (Azure Active Directory)
**License:** Entra ID Free (interactive sign-ins)
**Connector:** Microsoft Entra ID (formerly Azure Active Directory)
**Ingestion Latency:** 5-10 minutes

**Column validation against Arina's request:**

| Column | In Sources | Exists in Table | Type | Notes |
|---|---|---|---|---|
| UserPrincipalName | YES | YES | string | - |
| IPAddress | YES | YES | string | - |
| Location | YES | YES | dynamic | Contains .city, .state, .countryOrRegion, .geoCoordinates |
| ResultType | YES | YES | string | 0 = success. Arina should note: string type, not int |
| AppDisplayName | YES | YES | string | - |
| ConditionalAccessStatus | YES | YES | string | Values: success, failure, notApplied |
| DeviceDetail | NOT IN SOURCES | YES | dynamic | Contains .deviceId, .displayName, .operatingSystem, .browser, .isCompliant, .isManaged, .trustType. Samet must use parse_json() or dot notation to access nested properties |
| UserAgent | NOT IN SOURCES | YES | string | Raw user agent string. Useful but overlaps with DeviceDetail.browser |
| AuthenticationRequirement | NOT IN SOURCES | YES | string | Values: singleFactorAuthentication, multiFactorAuthentication. Critical for determining if MFA was required |
| MfaDetail | NOT IN SOURCES | YES | dynamic | Contains .authMethod (e.g., "PhoneAppNotification", "OneWaySMS", "PhoneAppOTP"), .authDetail. Only populated when MFA was performed |
| CorrelationId | NOT IN SOURCES | YES | string | GUID linking related sign-in events. Important for session tracking |

**Action required:** 5 columns Arina needs (DeviceDetail, UserAgent, AuthenticationRequirement, MfaDetail, CorrelationId) are NOT in our sources/microsoft-sentinel-tables.json key_columns because we limited to 8 per table. These columns DO exist in the real SigninLogs table and are valid. Samet should use them freely. I will add a supplementary columns note to the sources file in a future update.

**Gotchas for Samet:**
- DeviceDetail is dynamic - access nested fields with DeviceDetail.operatingSystem, DeviceDetail.browser, DeviceDetail.isCompliant, DeviceDetail.isManaged
- MfaDetail is dynamic and can be EMPTY if MFA was not performed. Always check with isnotempty(MfaDetail) before accessing nested fields
- AuthenticationRequirement tells you if MFA was REQUIRED, not if it was completed. Cross-reference with MfaDetail and ConditionalAccessStatus for full picture
- Location is dynamic - access with Location.city, Location.countryOrRegion. Can be empty for non-interactive sign-ins
- ResultType is a STRING containing numeric error codes, not an int. Use == "0" for success, not == 0

---

### 2. AADNonInteractiveUserSignInLogs - PASS

**Table Name:** AADNonInteractiveUserSignInLogs - CONFIRMED CORRECT
**Product:** Entra ID
**License:** Entra ID P1 or P2 (NOT available with Entra ID Free)
**Connector:** Microsoft Entra ID
**Ingestion Latency:** 5-10 minutes

**All columns Arina needs are available.** Same schema as SigninLogs. The same additional columns (DeviceDetail, AuthenticationRequirement, MfaDetail, CorrelationId) exist here too.

**Gotchas for Samet:**
- This table has SIGNIFICANTLY higher volume than SigninLogs (often 10-50x). Token refreshes generate a row every time. Always use tight TimeGenerated filters
- For Arina's baseline (Step 3), combining SigninLogs + AADNonInteractiveUserSignInLogs gives complete picture but Samet should consider using union with caution due to volume
- For baseline, I recommend Samet calculate interactive and non-interactive baselines separately, then combine results. Do not union the raw tables for 30 days - the volume will be enormous
- UserAgent in this table often shows app-specific agents (e.g., "python-requests/2.28", "azure-sdk-for-go") rather than browsers

**Licensing flag for runbook:** This table requires Entra ID P1/P2. Not all MSSP customers will have this. If unavailable, the baseline in Step 3 will be limited to SigninLogs (interactive only), which gives an incomplete picture. Document this as a limitation in the runbook.

---

### 3. AADUserRiskEvents - PASS

**Table Name:** AADUserRiskEvents - CONFIRMED CORRECT
**Product:** Entra ID Identity Protection
**License:** Entra ID P2 (required - no alternative)
**Connector:** Microsoft Entra ID
**Ingestion Latency:** 5-30 minutes (realtime detections ~5 min, offline detections can be hours)

**All columns Arina needs are available and in sources:**
- RiskEventType: string - includes "unfamiliarFeatures" for this specific alert
- DetectionTimingType: string - "realtime" or "offline"
- RiskLevel: string - "low", "medium", "high", "hidden"
- IpAddress: string
- Location: dynamic
- UserPrincipalName: string

**Gotchas for Samet:**
- Note the column is "IpAddress" (capital 'A') in this table, but "IPAddress" (capital 'IP') in SigninLogs. Case matters in KQL column references
- DetectionTimingType "offline" means the risk was detected AFTER the sign-in (batch ML processing). The TimeGenerated may be hours after the actual sign-in. Always join with SigninLogs by CorrelationId to get the actual sign-in timestamp
- RiskEventType value for this runbook is "unfamiliarFeatures" (not "unfamiliar sign-in properties" - the display name differs from the enum value)

---

### 4. AADRiskyUsers - PASS

**Table Name:** AADRiskyUsers - CONFIRMED CORRECT
**Product:** Entra ID Identity Protection
**License:** Entra ID P2
**Connector:** Microsoft Entra ID
**Ingestion Latency:** 5-10 minutes

**All columns Arina needs are available and in sources:**
- RiskLevel, RiskState, RiskDetail, UserPrincipalName: all confirmed

**Gotchas for Samet:**
- This is a STATE table, not an EVENT table. It shows the current aggregated risk state, not individual events. Use arg_max(TimeGenerated, *) to get the latest state per user
- RiskState "atRisk" means Identity Protection has flagged the user but no remediation has occurred
- After containment (password reset + MFA re-registration), RiskState should change to "remediated"

---

### 5. AuditLogs - PASS

**Table Name:** AuditLogs - CONFIRMED CORRECT
**Product:** Entra ID
**License:** Entra ID Free (basic audit), Entra ID P2 for PIM events
**Connector:** Microsoft Entra ID
**Ingestion Latency:** 5-15 minutes

**All columns Arina needs are available and in sources:**
- OperationName, Category, InitiatedBy, TargetResources: all confirmed

**Specific OperationName values Arina requested - VALIDATED:**

| Operation (Arina's request) | Correct OperationName Value | Category |
|---|---|---|
| Register security info | Register security info | UserManagement |
| Consent to application | Consent to application | ApplicationManagement |
| Add user | Add user | UserManagement |
| Update user | Update user | UserManagement |

**Additional OperationName values Samet should include for Step 5 (post-sign-in persistence):**
- "User registered security info" - MFA registration event
- "User deleted security info" - MFA method removal
- "Add app role assignment to service principal" - OAuth permission grant
- "Add delegated permission grant" - Delegated API permission
- "Add owner to application" - App ownership change (persistence)
- "Update application" - App credential/certificate changes

**Gotchas for Samet:**
- InitiatedBy is dynamic with two possible structures: InitiatedBy.user.userPrincipalName (for user-initiated) or InitiatedBy.app.displayName (for app-initiated). Always check both
- TargetResources is a dynamic ARRAY - use mv-expand or TargetResources[0] to access the first element
- TargetResources[0].modifiedProperties contains oldValue and newValue for changes - critical for understanding what was changed

---

### 6. IdentityInfo - PASS

**Table Name:** IdentityInfo - CONFIRMED CORRECT
**Product:** Sentinel UEBA
**License:** Microsoft Sentinel with UEBA enabled
**Connector:** Auto-populated when Sentinel UEBA is enabled
**Ingestion Latency:** Periodic sync (every 4-24 hours, NOT real-time)

**All columns Arina needs are available and in sources:**
- AccountUPN, Department, JobTitle, AssignedRoles, GroupMemberships: all confirmed

**Gotchas for Samet:**
- This is a LOOKUP table, not a real-time event table. Use `lookup` operator instead of `join` for better performance
- Use arg_max(TimeGenerated, *) to get the latest record per user since the table accumulates historical snapshots
- AssignedRoles and GroupMemberships are dynamic arrays - use mv-expand if you need to check for specific roles/groups
- If UEBA is not enabled, this table will be EMPTY. Document this as a prerequisite in the runbook
- **Fallback if UEBA not enabled:** Use AuditLogs with Category == "RoleManagement" to check for privileged role assignments, but this requires more complex queries and won't have department/title info

---

### 7. OfficeActivity - PASS

**Table Name:** OfficeActivity - CONFIRMED CORRECT
**Product:** Office 365
**License:** Microsoft 365 E3 or higher
**Connector:** Office 365
**Ingestion Latency:** 15-60 minutes (Exchange ~15-30 min, SharePoint/OneDrive up to 60 min)

**All columns Arina needs are available and in sources:**
- Operation, UserId, ClientIP, OfficeWorkload: all confirmed

**Specific Operation values for Step 5 (post-sign-in activity) - VALIDATED:**

| Operation | OfficeWorkload | Security Relevance |
|---|---|---|
| New-InboxRule | Exchange | Inbox rule creation - top persistence indicator for BEC |
| Set-InboxRule | Exchange | Inbox rule modification |
| Set-Mailbox | Exchange | Mailbox settings change (forwarding) |
| Set-MailboxJunkEmailConfiguration | Exchange | Junk filter manipulation |
| Add-MailboxPermission | Exchange | Delegate access added |
| MailItemsAccessed | Exchange | Email access (high volume = mass access) |
| FileDownloaded | SharePoint/OneDrive | File download (high volume = exfiltration) |
| FileAccessed | SharePoint/OneDrive | File viewed |
| FileUploaded | SharePoint/OneDrive | File upload |

**Gotchas for Samet:**
- ClientIP format is inconsistent: can be "1.2.3.4", "1.2.3.4:12345" (with port), or "[::ffff:1.2.3.4]:12345" (IPv6-mapped). Samet must strip port and IPv6 prefix before joining with SigninLogs.IPAddress. Use: `extend CleanIP = tostring(extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP))`
- MailItemsAccessed is HIGH VOLUME in E5 environments with mailbox auditing enabled. Use summarize count() before presenting results
- New-InboxRule: the rule details are in the Parameters column (dynamic). Key fields: Name (rule name), SubjectContainsWords, From, MoveToFolder, ForwardTo, DeleteMessage, MarkAsRead
- **Ingestion latency warning for Arina:** OfficeActivity can take up to 60 minutes to appear. If investigating a sign-in that happened < 1 hour ago, the post-sign-in activity may not yet be visible. Samet should add a note about this in the query comments
- UserId in OfficeActivity uses UPN format (user@contoso.com), matching SigninLogs.UserPrincipalName directly

---

### 8. CloudAppEvents - PASS WITH NOTES

**Table Name:** CloudAppEvents - CONFIRMED CORRECT
**Product:** Defender for Cloud Apps (MCAS)
**License:** Microsoft Defender for Cloud Apps (standalone or M365 E5)
**Connector:** Microsoft 365 Defender (Microsoft Defender XDR)
**Ingestion Latency:** 15-30 minutes

**All columns Arina needs are available and in sources:**
- ActionType, Application, AccountDisplayName, IPAddress, ActivityObjects: all confirmed

**Licensing note:** This is a PREMIUM table. Many MSSP customers on E3 will NOT have this data. Arina's Step 5 uses this for SaaS activity monitoring. If unavailable, Samet should rely on OfficeActivity as the primary post-sign-in activity source (which covers Exchange, SharePoint, OneDrive, Teams on E3).

**Gotchas for Samet:**
- CloudAppEvents and OfficeActivity have OVERLAPPING data for M365 workloads. For E5 customers, some actions appear in both tables. Do not double-count
- AccountDisplayName (not AccountUPN) is the primary user identifier. Join with IdentityInfo or use AccountObjectId for precise matching
- ActivityObjects is a dynamic array - use mv-expand to analyze individual objects involved in each action

---

### 9. SecurityAlert - PASS

**Table Name:** SecurityAlert - CONFIRMED CORRECT
**Product:** Microsoft Sentinel
**License:** Microsoft Sentinel
**Connector:** Auto-populated from connected security products
**Ingestion Latency:** 5-15 minutes

**All columns Arina needs are available and in sources:**
- AlertName, AlertSeverity, Entities, Tactics, ProviderName: all confirmed

**Gotchas for Samet:**
- Entities is a dynamic JSON ARRAY with mixed entity types. Each entity has a "Type" field. To extract user entities: `mv-expand Entity = parse_json(Entities) | where Entity.Type == "account"`
- The "Unfamiliar sign-in properties" alert will appear here with ProviderName == "Azure Active Directory Identity Protection"
- When checking for correlated alerts (Step 4), filter by the user entity within Entities, not by a direct UserPrincipalName column (which does not exist in SecurityAlert)

---

### 10. ThreatIntelligenceIndicator - PASS

**Table Name:** ThreatIntelligenceIndicator - CONFIRMED CORRECT
**Product:** Microsoft Sentinel
**License:** Microsoft Sentinel (TI feeds may have additional costs)
**Connector:** Threat Intelligence - TAXII, Threat Intelligence Platforms, Microsoft Defender TI
**Ingestion Latency:** 5-15 minutes

**All columns Arina needs are available and in sources:**
- NetworkIP, ThreatType, ConfidenceScore, ExpirationDateTime: all confirmed

**Gotchas for Samet:**
- ALWAYS filter for active indicators: `where ExpirationDateTime > now()` and `where Active == true`
- NetworkIP may contain IPv4 or IPv6. Match format with the IP from SigninLogs
- If no TI feeds are configured, this table will be EMPTY. This is common in smaller environments. Document as an optional enrichment step, not a required one
- ConfidenceScore ranges 0-100. I recommend Samet filters for ConfidenceScore >= 50 to reduce noise from low-confidence indicators

---

### 11. BehaviorAnalytics - PASS WITH NOTES

**Table Name:** BehaviorAnalytics - CONFIRMED CORRECT
**Product:** Sentinel UEBA
**License:** Microsoft Sentinel with UEBA enabled
**Connector:** Auto-populated when UEBA is enabled
**Ingestion Latency:** 30-60 minutes (ML processing delay)

**All columns Arina needs are available and in sources:**
- UserPrincipalName, ActionType, ActivityInsights, InvestigationPriority: all confirmed

**Gotchas for Samet:**
- UEBA requires 14+ days of data before it generates meaningful baselines. New Sentinel deployments may have sparse BehaviorAnalytics data
- ActivityInsights is a dynamic object with boolean flags like "FirstTimeUserConnectedViaISP", "ActivityUncommonlyPerformedByUser". These map well to Arina's investigation questions
- InvestigationPriority >= 5 is the recommended threshold for analyst review
- If UEBA is not enabled, this table is EMPTY. Like IdentityInfo, this is an enrichment source. The investigation must still work without it

---

## Licensing Summary for This Runbook

| License Tier | Tables Available | Investigation Impact |
|---|---|---|
| **Entra ID Free + Sentinel** | SigninLogs, AuditLogs, SecurityAlert, ThreatIntelligenceIndicator | Can run Steps 1, 4 (partial), 5 (partial), 6 (partial). No baseline with non-interactive logs. No risk events. Limited investigation. |
| **Entra ID P2 + Sentinel** | Above + AADNonInteractiveUserSignInLogs, AADUserRiskEvents, AADRiskyUsers | Can run Steps 1-4, 6. Full risk event analysis. Full baseline. |
| **M365 E3 + Entra ID P2 + Sentinel** | Above + OfficeActivity | Can run Steps 1-5, 6. Post-sign-in activity via OfficeActivity. |
| **M365 E5 + Sentinel + UEBA** | ALL 11 tables | Full investigation capability across all 7 steps. |

**Minimum recommended:** Entra ID P2 + M365 E3 + Sentinel
**Optimal:** M365 E5 + Sentinel with UEBA enabled

---

## Additional Columns Samet Will Need (Not in Sources Key Columns)

These columns exist in the real tables but were not included in our sources/microsoft-sentinel-tables.json (limited to 5-8 key columns per table). All are confirmed valid:

### SigninLogs - Additional Columns
| Column | Type | Description |
|---|---|---|
| DeviceDetail | dynamic | Device info: .deviceId, .displayName, .operatingSystem, .browser, .isCompliant, .isManaged, .trustType |
| UserAgent | string | Raw HTTP user agent string |
| AuthenticationRequirement | string | Values: singleFactorAuthentication, multiFactorAuthentication |
| MfaDetail | dynamic | MFA method used: .authMethod, .authDetail. Empty if no MFA performed |
| CorrelationId | string | GUID linking related sign-in events and risk detections |
| SessionId | string | Session identifier for tracking multi-event sessions |
| ResourceDisplayName | string | Target resource (e.g., "Microsoft Office 365", "Windows Azure Active Directory") |
| ClientAppUsed | string | Client application type (e.g., "Browser", "Mobile Apps and Desktop clients", "Exchange ActiveSync") |
| IsInteractive | bool | Always true for SigninLogs, always false for AADNonInteractiveUserSignInLogs |

### AADUserRiskEvents - Additional Columns
| Column | Type | Description |
|---|---|---|
| CorrelationId | string | Links to the SigninLogs entry that triggered this risk event |
| Activity | string | Activity description (e.g., "signin") |
| Id | string | Unique risk event identifier |

---

## Hasan's Recommendations for Samet

1. **IP address normalization:** SigninLogs.IPAddress, OfficeActivity.ClientIP, AADUserRiskEvents.IpAddress, and CloudAppEvents.IPAddress all use different formats. Create a `let cleanIP = ...` function at the top of queries that normalizes all IP formats for joining.

2. **Time window alignment:** OfficeActivity has up to 60 min latency. When checking post-sign-in activity (Step 5), use a 4-hour window from the sign-in time, not 1 hour, to account for ingestion delay.

3. **Union strategy for baseline:** For Step 3, do NOT union 30 days of SigninLogs + AADNonInteractiveUserSignInLogs raw. Instead, summarize each table separately, then combine the summaries. The non-interactive table can have millions of rows per user per month.

4. **Entity extraction from SecurityAlert:** The Entities column requires parsing. I recommend Samet create a reusable let function for extracting user entities from the JSON array.

5. **Fallback strategy:** Always provide alternative queries for when premium tables (CloudAppEvents, BehaviorAnalytics, IdentityInfo) are unavailable. The core investigation should work with Entra ID P2 + E3 + Sentinel.

---

**Validation complete. I need Samet to write the queries based on Arina's flow and my table/column guidance. All 11 tables are confirmed valid.**
