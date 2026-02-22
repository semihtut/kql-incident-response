# Getting Started

This guide covers everything you need to start using the KQL Incident Response Playbooks in your Microsoft Sentinel environment.

## Prerequisites

### Access Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Azure Portal access | Reader | Microsoft Sentinel Responder |
| Log Analytics workspace | Log Analytics Reader | Log Analytics Contributor |
| Microsoft Sentinel | Microsoft Sentinel Reader | Microsoft Sentinel Responder |

### License Tiers

Runbooks reference tables from multiple Microsoft products. Each runbook lists its required log sources and the minimum license tier needed:

| License Tier | Tables Available | Example Products |
|--------------|------------------|-----------------|
| Entra ID Free | SigninLogs, AuditLogs | Basic sign-in and directory audit |
| Entra ID P1 | + AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs | Non-interactive and service principal sign-ins |
| Entra ID P2 | + AADUserRiskEvents, AADRiskyUsers | Identity Protection risk detections |
| M365 E3 | + OfficeActivity | Office 365 audit logs (Exchange, SharePoint, Teams) |
| M365 E5 | + EmailEvents, DeviceEvents, CloudAppEvents | Full Defender XDR suite |
| Sentinel | + SecurityAlert, SecurityIncident, BehaviorAnalytics | SIEM correlation and UEBA |

!!! note
    You don't need every license to use the runbooks. Each runbook's metadata section lists required vs. optional log sources, so you can run partial investigations with whatever data you have available.

### Platform Compatibility

These runbooks are written for **Microsoft Sentinel** (Log Analytics workspace). If you're running queries in a different platform, be aware of these differences:

| Aspect | Microsoft Sentinel | Defender XDR (Advanced Hunting) |
|--------|-------------------|-------------------------------|
| Time column | `TimeGenerated` | `Timestamp` |
| Sign-in logs | `SigninLogs` | `AADSignInEventsBeta` |
| Audit logs | `AuditLogs` | `CloudAppEvents` |
| Office activity | `OfficeActivity` | `EmailEvents`, `CloudAppEvents` |
| Risk events | `AADUserRiskEvents` | Not available |
| Query language | KQL (full) | KQL (subset) |

!!! warning "Table Names May Vary"
    Table names and schemas can change as Microsoft updates its products. If a query returns no results, verify that the table exists in your environment by running `TableName | take 1`. Check the [Log Sources Reference](log-sources.md) for current table details.

## How to Use a Runbook

### 1. Identify the Alert

Each runbook is named after the Microsoft security alert it investigates. When you receive an alert in Sentinel, find the matching runbook in the [Runbooks](runbooks/index.md) section.

### 2. Check the Metadata

Every runbook starts with a YAML metadata block that tells you:

- **Severity** - How critical this alert type typically is
- **MITRE ATT&CK mapping** - Which tactics and techniques are involved
- **Log sources** - Which tables you need and their license requirements
- **Threat actors** - Known groups that use this technique

### 3. Follow the Investigation Steps

Runbooks are organized as numbered investigation steps. Each step includes:

- **Purpose** - Why you're running this query
- **KQL query** - Copy-paste ready query for Sentinel Log Analytics
- **What to look for** - Specific indicators and thresholds
- **Decision points** - What to do based on the results

### 4. Run KQL Queries

Open **Microsoft Sentinel > Logs** in the Azure portal and paste the KQL queries. Each query is **self-contained** — you can copy-paste and run any step independently.

**Replace the investigation parameters** at the top of each query with your alert details:

```kql
let AlertTime = datetime(2026-02-22T08:15:00Z);  // UTC time from your alert
let TargetUser = "user@contoso.com";              // Affected user's UPN
```

**How to find the correct AlertTime:**

1. Open your incident in **Sentinel > Incidents**
2. Copy the **First activity** time from the incident details pane
3. Paste it in ISO 8601 / UTC format: `YYYY-MM-DDTHH:MM:SSZ`

!!! tip "TimeGenerated vs Event Time"
    Queries filter on `TimeGenerated` (when Sentinel ingested the log), which may differ slightly from the actual event time. All queries use generous time windows (typically ±2h to ±4h around AlertTime) to account for ingestion delays. If you suspect significant lag, widen the `LookbackWindow` parameter.

### 5. Follow the Decision Tree

Each runbook includes decision points that guide you through branching logic:

- If the activity is confirmed malicious, proceed to **Containment Actions**
- If the activity is benign, document your findings and close the alert
- If you need more context, the runbook directs you to additional investigation steps

## Runbook Structure

Every runbook follows a consistent format:

| Section | Purpose |
|---------|---------|
| Metadata | Alert name, severity, MITRE mapping, log sources, license requirements |
| Investigation Steps | Ordered KQL queries with explanations and decision points |
| Baseline Comparison | Statistical comparison against normal behavior patterns |
| Containment Actions | Specific remediation steps and commands |
| Evidence Collection | What to preserve for forensic analysis |
| Sample Data | Synthetic `datatable`-based test data for validation |

## Running Queries Locally

You can validate queries without production access using the synthetic test data included in each runbook. The `datatable` operator creates inline test tables that simulate real log data:

```kql
let test_data = datatable(TimeGenerated: datetime, UserPrincipalName: string, IPAddress: string) [
    datetime(2025-01-15T10:00:00Z), "user@contoso.com", "198.51.100.1",
    datetime(2025-01-15T10:05:00Z), "user@contoso.com", "203.0.113.50"
];
test_data
| where IPAddress != "198.51.100.1"
```

## Next Steps

- Browse [Runbooks](runbooks/index.md) to find investigation guides
- Review [Log Sources](log-sources.md) to understand available tables
- Check [MITRE Coverage](mitre-coverage.md) to see technique mappings
- Read [Contributing](contributing.md) if you want to add runbooks
