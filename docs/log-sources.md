# Log Sources Reference

Complete reference of all Microsoft Sentinel log tables used in the KQL Incident Response Playbooks. Each table includes its description, required license, data connector, and typical ingestion latency.

This reference is auto-generated from [`sources/microsoft-sentinel-tables.json`](https://github.com/leoparkkisaari/kql-incident-response/blob/main/sources/microsoft-sentinel-tables.json).

---

## Entra ID

| Table Name | Description | License | Connector | Latency |
|------------|-------------|---------|-----------|---------|
| [SigninLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs) | Interactive user sign-in events to Entra ID (Azure AD). | Entra ID Free (interactive sign-ins) | Microsoft Entra ID (formerly Azure Active Directory) | 5-10 minutes |
| [AADNonInteractiveUserSignInLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs) | Non-interactive user sign-in events. | Entra ID P1 or P2 | Microsoft Entra ID (formerly Azure Active Directory) | 5-10 minutes |
| [AADServicePrincipalSignInLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs) | Service principal (application) sign-in events. | Entra ID P1 or P2 | Microsoft Entra ID (formerly Azure Active Directory) | 5-10 minutes |
| [AADManagedIdentitySignInLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadmanagedidentitysigninlogs) | Managed identity sign-in events. | Entra ID P1 or P2 | Microsoft Entra ID (formerly Azure Active Directory) | 5-10 minutes |
| [AuditLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs) | Entra ID directory audit logs. | Entra ID Free (basic audit), Entra ID P2 for PIM audit events | Microsoft Entra ID (formerly Azure Active Directory) | 5-15 minutes |

## Identity Protection

| Table Name | Description | License | Connector | Latency |
|------------|-------------|---------|-----------|---------|
| [AADRiskyUsers](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadriskyusers) | Users flagged as risky by Entra ID Identity Protection. | Entra ID P2 | Microsoft Entra ID (formerly Azure Active Directory) | 5-10 minutes |
| [AADUserRiskEvents](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aaduserriskevents) | Individual risk detection events for users from Entra ID Identity Protection. | Entra ID P2 | Microsoft Entra ID (formerly Azure Active Directory) | 5-30 minutes (realtime detections ~5 min, offline detections can be hours) |
| [AADRiskyServicePrincipals](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadriskyserviceprincipals) | Service principals (applications) flagged as risky by Entra ID Identity Protection. | Entra ID P2 + Workload Identities Premium | Microsoft Entra ID (formerly Azure Active Directory) | 5-15 minutes |
| [AADServicePrincipalRiskEvents](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalriskevents) | Individual risk detection events for service principals from Entra ID Identity Protection. | Entra ID P2 + Workload Identities Premium | Microsoft Entra ID (formerly Azure Active Directory) | 5-30 minutes (realtime ~5 min, offline can be hours) |

## Defender for Endpoint

| Table Name | Description | License | Connector | Latency |
|------------|-------------|---------|-----------|---------|
| [DeviceEvents](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/deviceevents) | General endpoint activity events from Microsoft Defender for Endpoint. | Microsoft Defender for Endpoint P2 | Microsoft 365 Defender (Microsoft Defender XDR) | 5-20 minutes |
| [DeviceLogonEvents](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/devicelogonevents) | Endpoint logon and authentication events from Defender for Endpoint. | Microsoft Defender for Endpoint P2 | Microsoft 365 Defender (Microsoft Defender XDR) | 5-20 minutes |
| [DeviceFileEvents](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/devicefileevents) | File creation, modification, and deletion events from Defender for Endpoint. | Microsoft Defender for Endpoint P2 | Microsoft 365 Defender (Microsoft Defender XDR) | 5-20 minutes |
| [DeviceProcessEvents](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/deviceprocessevents) | Process creation and execution events from Defender for Endpoint. | Microsoft Defender for Endpoint P2 | Microsoft 365 Defender (Microsoft Defender XDR) | 5-20 minutes |
| [DeviceNetworkEvents](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/devicenetworkevents) | Network connection events from Defender for Endpoint. | Microsoft Defender for Endpoint P2 | Microsoft 365 Defender (Microsoft Defender XDR) | 5-20 minutes |
| [DeviceRegistryEvents](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/deviceregistryevents) | Windows registry modification events from Defender for Endpoint. | Microsoft Defender for Endpoint P2 | Microsoft 365 Defender (Microsoft Defender XDR) | 5-20 minutes |
| [DeviceImageLoadEvents](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/deviceimageloadevents) | DLL and image loading events from Defender for Endpoint. | Microsoft Defender for Endpoint P2 | Microsoft 365 Defender (Microsoft Defender XDR) | 5-20 minutes |
| [AlertEvidence](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/alertevidence) | Evidence entities associated with alerts from Microsoft 365 Defender (Defender XDR). | Microsoft Defender for Endpoint P2 (or any Microsoft 365 Defender workload) | Microsoft 365 Defender (Microsoft Defender XDR) | 5-20 minutes |
| [AlertInfo](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/alertinfo) | Alert metadata from all Microsoft 365 Defender workloads (Defender for Endpoint, Office 365, Identity, Cloud Apps). | Microsoft Defender for Endpoint P2 (or any Microsoft 365 Defender workload) | Microsoft 365 Defender (Microsoft Defender XDR) | 5-20 minutes |

## Defender for Office 365

| Table Name | Description | License | Connector | Latency |
|------------|-------------|---------|-----------|---------|
| [EmailEvents](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/emailevents) | Email message flow events from Microsoft Defender for Office 365. | Microsoft Defender for Office 365 P2 | Microsoft 365 Defender (Microsoft Defender XDR) | 10-30 minutes |
| [EmailUrlInfo](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/emailurlinfo) | URLs extracted from email messages by Defender for Office 365. | Microsoft Defender for Office 365 P2 | Microsoft 365 Defender (Microsoft Defender XDR) | 10-30 minutes |
| [EmailAttachmentInfo](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/emailattachmentinfo) | Email attachment metadata from Defender for Office 365. | Microsoft Defender for Office 365 P2 | Microsoft 365 Defender (Microsoft Defender XDR) | 10-30 minutes |
| [EmailPostDeliveryEvents](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/emailpostdeliveryevents) | Post-delivery actions taken on email messages by Defender for Office 365. | Microsoft Defender for Office 365 P2 | Microsoft 365 Defender (Microsoft Defender XDR) | 10-30 minutes |
| [UrlClickEvents](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/urlclickevents) | SafeLinks URL click tracking events from Defender for Office 365. | Microsoft Defender for Office 365 P2 | Microsoft 365 Defender (Microsoft Defender XDR) | 10-30 minutes |

## Defender for Cloud Apps

| Table Name | Description | License | Connector | Latency |
|------------|-------------|---------|-----------|---------|
| [CloudAppEvents](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/cloudappevents) | SaaS application activity events from Microsoft Defender for Cloud Apps (formerly MCAS). | Microsoft Defender for Cloud Apps (standalone or as part of Microsoft 365 E5) | Microsoft 365 Defender (Microsoft Defender XDR) | 15-30 minutes |
| [McasShadowItReporting](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/mcasshadowitreporting) | Shadow IT discovery data from Defender for Cloud Apps. | Microsoft Defender for Cloud Apps (standalone or as part of Microsoft 365 E5) | Microsoft Defender for Cloud Apps | 30-60 minutes (aggregated reporting, not real-time) |

## Defender for Identity

| Table Name | Description | License | Connector | Latency |
|------------|-------------|---------|-----------|---------|
| [IdentityLogonEvents](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/identitylogonevents) | On-premises Active Directory authentication events from Microsoft Defender for Identity. | Microsoft Defender for Identity | Microsoft 365 Defender (Microsoft Defender XDR) | 5-15 minutes |
| [IdentityDirectoryEvents](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/identitydirectoryevents) | Active Directory directory change events from Microsoft Defender for Identity. | Microsoft Defender for Identity | Microsoft 365 Defender (Microsoft Defender XDR) | 5-15 minutes |
| [IdentityQueryEvents](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/identityqueryevents) | LDAP and DNS query events from Microsoft Defender for Identity. | Microsoft Defender for Identity | Microsoft 365 Defender (Microsoft Defender XDR) | 5-15 minutes |

## Office 365 Productivity

| Table Name | Description | License | Connector | Latency |
|------------|-------------|---------|-----------|---------|
| [OfficeActivity](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity) | Office 365 unified activity log capturing user and admin operations across Exchange Online, SharePoint Online, OneDrive for Business, Microsoft Teams, and Azure Active Directory. | Microsoft 365 E3 or higher (included with most M365 business plans) | Office 365 | 15-60 minutes (Exchange typically faster at 15-30 min, SharePoint/OneDrive can take up to 60 min) |

## Azure Infrastructure

| Table Name | Description | License | Connector | Latency |
|------------|-------------|---------|-----------|---------|
| [AzureActivity](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity) | Azure control plane (Azure Resource Manager) activity log. | Free with Azure subscription (no additional cost) | Azure Activity | 15-30 minutes |
| [AzureDiagnostics](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azurediagnostics) | Azure resource-level diagnostic logs. | Free (no additional cost for diagnostic logs themselves, but Log Analytics ingestion costs apply) | Azure Diagnostics (per-resource diagnostic settings must be configured) | 5-15 minutes (varies by resource type; Key Vault ~5 min, Storage ~10-15 min, Firewall ~5-10 min) |
| [AzureMetrics](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azuremetrics) | Performance and health metrics from Azure resources. | Free with Azure subscription (no additional cost for platform metrics) | Azure Diagnostics (metric export must be configured per resource) | 5-10 minutes |

## Security & Compliance

| Table Name | Description | License | Connector | Latency |
|------------|-------------|---------|-----------|---------|
| [SecurityAlert](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityalert) | Aggregated security alerts from all Microsoft security products ingested into Sentinel. | Microsoft Sentinel (alerts from connected products require their respective licenses) | Varies by source product (auto-populated when product connectors are enabled) | 5-15 minutes (depends on source product; Identity Protection alerts may take longer for offline detections) |
| [SecurityIncident](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityincident) | Microsoft Sentinel incidents created from correlated security alerts. | Microsoft Sentinel | Auto-populated by Sentinel analytics rules and alert grouping | 1-5 minutes (incidents are created by Sentinel itself) |
| [SecurityRecommendation](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityrecommendation) | Security posture recommendations from Microsoft Defender for Cloud. | Microsoft Defender for Cloud (Free tier provides basic recommendations, paid plans provide additional) | Microsoft Defender for Cloud | 30-60 minutes (assessment cycles run periodically, not real-time) |
| [ThreatIntelligenceIndicator](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/threatintelligenceindicator) | Threat intelligence indicators of compromise (IOCs) ingested into Microsoft Sentinel. | Microsoft Sentinel (TI feed subscriptions may require additional licensing depending on source) | Threat Intelligence - TAXII, Threat Intelligence Platforms, Microsoft Defender Threat Intelligence | 5-15 minutes (depends on TI feed polling interval) |

## UEBA (User & Entity Behavior Analytics)

| Table Name | Description | License | Connector | Latency |
|------------|-------------|---------|-----------|---------|
| [BehaviorAnalytics](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/behavioranalytics) | ML-based user and entity behavior analytics from Microsoft Sentinel UEBA. | Microsoft Sentinel with UEBA enabled | Auto-populated when Sentinel UEBA is enabled (Settings > Entity behavior > Enable UEBA) | 30-60 minutes (ML processing adds delay beyond source log ingestion) |
| [UserAccessAnalytics](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/useraccessanalytics) | User access pattern analytics from Microsoft Sentinel UEBA. | Microsoft Sentinel with UEBA enabled | Auto-populated when Sentinel UEBA is enabled | 60-120 minutes (batch processing of access patterns) |
| [UserPeerAnalytics](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/userpeeranalytics) | Peer group comparison analytics from Microsoft Sentinel UEBA. | Microsoft Sentinel with UEBA enabled | Auto-populated when Sentinel UEBA is enabled | 60-120 minutes (batch processing of peer group models) |
| [IdentityInfo](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/identityinfo) | User identity enrichment table from Microsoft Sentinel UEBA. | Microsoft Sentinel with UEBA enabled | Auto-populated when Sentinel UEBA is enabled (syncs from Entra ID) | Periodic sync (every 4-24 hours, not real-time) |

## Third-Party: Okta

| Table Name | Description | License | Connector | Latency |
|------------|-------------|---------|-----------|---------|
| [Okta_CL](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/okta-single-sign-on) | Okta system log events via the legacy custom log connector. | Okta tenant (any plan) + Sentinel custom log connector configured | Custom Logs via Azure Function (Okta API polling) or Logstash | 5-15 minutes (depends on Azure Function polling interval, typically 5 min) |
| [OktaSSO](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/okta-single-sign-on) | Okta Single Sign-On events via the native Sentinel connector (preview). | Okta tenant + Sentinel native Okta connector (preview) | Okta Single Sign-On (Preview) - native Sentinel data connector | 5-15 minutes |
| [OktaV2_CL](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/okta-single-sign-on) | Okta system log events via the V2 custom log connector. | Okta tenant (any plan) + Sentinel V2 custom log connector configured | Custom Logs V2 via Azure Function (Okta System Log API v2 polling) | 5-15 minutes (depends on Azure Function polling interval) |

---

## Summary

| Category | Table Count |
|----------|-------------|
| Entra ID | 5 |
| Identity Protection | 4 |
| Defender for Endpoint | 9 |
| Defender for Office 365 | 5 |
| Defender for Cloud Apps | 2 |
| Defender for Identity | 3 |
| Office 365 Productivity | 1 |
| Azure Infrastructure | 3 |
| Security & Compliance | 4 |
| UEBA (User & Entity Behavior Analytics) | 4 |
| Third-Party: Okta | 3 |
| **Total** | **43** |
