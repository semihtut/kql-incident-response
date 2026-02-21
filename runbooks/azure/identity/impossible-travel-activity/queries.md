# Query Reference - Impossible Travel Activity (RB-0002)

> **Author:** Samet (KQL Engineer)
> **Reviewed by:** Hasan (Platform Architect), Alp (QA Lead)
> **Version:** 1.0

## Query Inventory

| # | Query | Step | Tables | Purpose | Estimated Runtime |
|---|---|---|---|---|---|
| 1 | Extract Sign-In Pair | Step 1 | AADUserRiskEvents, SigninLogs | Extract risk event and both sign-in records | <5s |
| 2 | Geographic Distance | Step 2 | SigninLogs | Calculate distance and travel speed using geo_distance_2points() | <5s |
| 3A | Travel Pattern Baseline | Step 3 | SigninLogs | 30-day geographic footprint and VPN switching frequency | 5-15s |
| 3B | Known Locations Detail | Step 3 | SigninLogs | List all known locations for analyst reference | 5-10s |
| 4 | Device Fingerprint | Step 4 | SigninLogs | Compare device details between both sign-ins | <5s |
| 5A | Token Replay Check | Step 5 | AADNonInteractiveUserSignInLogs | Non-interactive sign-ins from anomalous IP | 5-10s |
| 5B | Session Cross-IP | Step 5 | SigninLogs + AADNonInteractive | Same session from multiple IPs | 5-10s |
| 6A | Directory Changes | Step 6 | AuditLogs | Post-sign-in persistence detection | <5s |
| 6B | Email/File Activity | Step 6 | OfficeActivity | Post-sign-in email and file access | 5-10s |
| 6C | Inbox Rule Deep Dive | Step 6 | OfficeActivity | Inbox rule parameter extraction | <5s |
| 7A | TI Lookup (Both IPs) | Step 7 | ThreatIntelligenceIndicator | IP reputation for both IPs | <3s |
| 7B | Org IP Usage (Both IPs) | Step 7 | SigninLogs | Organizational usage of both IPs | 5-10s |
| 7C | UEBA Insights | Step 7 | BehaviorAnalytics | Behavioral anomaly detection | <5s |

## Key KQL Patterns Used

### geo_distance_2points()
```kql
// Calculate great-circle distance between two coordinates
// Note: longitude FIRST, then latitude
let distanceMeters = geo_distance_2points(lon1, lat1, lon2, lat2);
let distanceKm = distanceMeters / 1000.0;
```

### Travel speed calculation
```kql
let timeDiffHours = datetime_diff("second", time2, time1) / 3600.0;
let speedKmH = iff(timeDiffHours > 0, distanceKm / timeDiffHours, real(999999));
```

### Device fingerprint extraction
```kql
| extend
    DeviceId = tostring(DeviceDetail.deviceId),
    DeviceOS = tostring(DeviceDetail.operatingSystem),
    DeviceBrowser = tostring(DeviceDetail.browser)
```

### LocationDetails coordinate extraction
```kql
| extend
    Lat = toreal(tostring(LocationDetails.geoCoordinates.latitude)),
    Lon = toreal(tostring(LocationDetails.geoCoordinates.longitude))
```

### IP normalization for OfficeActivity
```kql
| extend CleanClientIP = extract(@"(\d+\.\d+\.\d+\.\d+)", 1, ClientIP)
```

### VPN switching detection (prev() pattern)
```kql
| order by TimeGenerated asc
| extend PrevIP = prev(IPAddress), PrevTime = prev(TimeGenerated)
| where IPAddress != PrevIP and isnotempty(PrevIP)
| extend TimeBetweenSwitchesMin = datetime_diff("minute", TimeGenerated, PrevTime)
| where TimeBetweenSwitchesMin <= 60
```

## Optimization Notes

1. **Always filter by user + time first** - these are the most selective predicates
2. **AADNonInteractiveUserSignInLogs is high volume** - always add IP filter when possible
3. **Use `summarize arg_max()` instead of `take 1`** for deterministic results
4. **geo_distance_2points() is fast** - O(1) per row, no external lookup
5. **Cross-join for max radius** can be expensive with many IPs - limit to 50 distinct IPs
6. **OfficeActivity latency** - up to 60 min. Re-run 2 hours after alert for completeness
