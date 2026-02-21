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

Open **Microsoft Sentinel > Logs** in the Azure portal and paste the KQL queries. Replace placeholder values (marked with comments in the queries) with your specific alert details:

- `<UserPrincipalName>` - The affected user's UPN
- `<IPAddress>` - The suspicious IP address
- `<TimeWindow>` - The investigation time range

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
