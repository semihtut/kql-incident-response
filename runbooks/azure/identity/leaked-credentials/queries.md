# Query Reference - Leaked Credentials (RB-0003)

> **Author:** Samet (KQL Engineer)
> **Reviewed by:** Hasan (Platform Architect), Alp (QA Lead)
> **Version:** 1.0

## Query Inventory

| # | Query | Step | Tables | Purpose | Estimated Runtime |
|---|---|---|---|---|---|
| 1 | Extract Risk Event | Step 1 | AADUserRiskEvents | Extract leaked credential risk event details | <5s |
| 2 | User Risk State & Password Timeline | Step 2 | AADRiskyUsers, AuditLogs | Check current risk state and password change history | <5s |
| 3 | Sign-In Baseline (30-day) | Step 3 | SigninLogs | Establish normal sign-in pattern for anomaly comparison | 5-15s |
| 4A | Anomalous Sign-In Detection | Step 4 | SigninLogs | Find sign-ins from new IPs/locations/devices post-leak | 5-10s |
| 4B | Non-Interactive Sign-In Check | Step 4 | AADNonInteractiveUserSignInLogs | Token usage from anomalous IPs | 5-10s |
| 5A | Directory Changes | Step 5 | AuditLogs | Post-sign-in persistence detection | <5s |
| 5B | Email/File Activity | Step 5 | OfficeActivity | Post-sign-in email and file access | 5-10s |
| 5C | Inbox Rule Deep Dive | Step 5 | OfficeActivity | Inbox rule parameter extraction | <5s |
| 6 | MFA & Legacy Auth Assessment | Step 6 | SigninLogs | Determine MFA coverage and legacy auth exposure | 5-10s |
| 7A | TI Lookup | Step 7 | ThreatIntelligenceIndicator | IP reputation for anomalous IPs | <3s |
| 7B | Org IP Usage | Step 7 | SigninLogs | Organizational usage of anomalous IPs | 5-10s |

## Key KQL Patterns Used

### Detecting password changes in AuditLogs
```kql
AuditLogs
| where OperationName in (
    "Change user password",
    "Reset user password",
    "Reset password (by admin)",
    "Change password (self-service)"
)
| where tostring(TargetResources[0].userPrincipalName) == targetUser
    or tostring(InitiatedBy.user.userPrincipalName) == targetUser
```

### Legacy auth detection
```kql
SigninLogs
| where ClientAppUsed in (
    "Exchange ActiveSync",
    "IMAP4", "POP3", "SMTP",
    "Other clients",
    "Authenticated SMTP"
)
```

### Failed sign-in analysis (credential testing)
```kql
SigninLogs
| where ResultType != "0"
| summarize
    FailedAttempts = count(),
    DistinctIPs = dcount(IPAddress),
    ResultCodes = make_set(ResultType)
    by UserPrincipalName
```

### Baseline IP comparison
```kql
let baselineIPs = SigninLogs
    | where TimeGenerated between (baselineStart .. baselineEnd)
    | where UserPrincipalName == targetUser
    | where ResultType == "0"
    | distinct IPAddress;
SigninLogs
| where TimeGenerated > alertTime
| where UserPrincipalName == targetUser
| where IPAddress !in (baselineIPs)
```

### IP normalization for OfficeActivity
```kql
| extend CleanClientIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)
```

## Optimization Notes

1. **Always filter by user + time first** - these are the most selective predicates
2. **Include failed sign-ins** - Unlike RB-0001/RB-0002, failed sign-ins are valuable here to detect credential testing
3. **AADNonInteractiveUserSignInLogs is high volume** - always add user filter when possible
4. **Password change detection** - Use AuditLogs with specific OperationName values, not SigninLogs
5. **Legacy auth queries** - Filter by ClientAppUsed to find MFA bypass vectors
6. **OfficeActivity latency** - up to 60 min. Re-run 2 hours after alert for completeness
