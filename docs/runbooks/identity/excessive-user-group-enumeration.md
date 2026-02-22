---
title: "Excessive User/Group Enumeration"
id: RB-0020
severity: high
status: reviewed
description: >
  Investigation runbook for detecting excessive enumeration of users, groups,
  and directory objects in Microsoft Entra ID via Microsoft Graph API or
  directory read operations. Covers high-volume Graph API call analysis,
  directory enumeration by service principals, user-initiated bulk directory
  queries, reconnaissance pattern identification, and organization-wide
  enumeration activity sweep. Directory enumeration is a key post-compromise
  reconnaissance step where attackers map the organizational structure to
  identify high-value targets, privileged accounts, security groups, and
  lateral movement paths.
mitre_attack:
  tactics:
    - tactic_id: TA0007
      tactic_name: "Discovery"
    - tactic_id: TA0043
      tactic_name: "Reconnaissance"
    - tactic_id: TA0008
      tactic_name: "Lateral Movement"
    - tactic_id: TA0009
      tactic_name: "Collection"
  techniques:
    - technique_id: T1087.004
      technique_name: "Account Discovery: Cloud Account"
      confidence: confirmed
    - technique_id: T1069.003
      technique_name: "Permission Groups Discovery: Cloud Groups"
      confidence: confirmed
    - technique_id: T1087
      technique_name: "Account Discovery"
      confidence: confirmed
    - technique_id: T1538
      technique_name: "Cloud Service Dashboard"
      confidence: probable
    - technique_id: T1580
      technique_name: "Cloud Infrastructure Discovery"
      confidence: probable
threat_actors:
  - "Midnight Blizzard (APT29)"
  - "Storm-0558"
  - "Scattered Spider (Octo Tempest)"
  - "LAPSUS$"
  - "Volt Typhoon"
log_sources:
  - table: "MicrosoftGraphActivityLogs"
    product: "Microsoft Graph"
    license: "Entra ID P1/P2 + Diagnostic Settings"
    required: true
    alternatives: ["AuditLogs"]
  - table: "AuditLogs"
    product: "Entra ID"
    license: "Entra ID Free"
    required: true
    alternatives: []
  - table: "SigninLogs"
    product: "Entra ID"
    license: "Entra ID Free"
    required: true
    alternatives: []
  - table: "AADServicePrincipalSignInLogs"
    product: "Entra ID"
    license: "Entra ID P1/P2"
    required: false
    alternatives: []
  - table: "BehaviorAnalytics"
    product: "Microsoft Sentinel"
    license: "Sentinel UEBA"
    required: false
    alternatives: []
author: "Leo (Coordinator), Arina (IR), Hasan (Platform), Samet (KQL), Yunus (TI), Alp (QA)"
created: 2026-02-22
updated: 2026-02-22
version: "1.0"
tier: 2
data_checks:
  - query: "MicrosoftGraphActivityLogs | take 1"
    label: primary
    description: "Graph API call logging for enumeration detection"
  - query: "AuditLogs | take 1"
    description: "For directory read and change operations"
  - query: "SigninLogs | take 1"
    description: "For actor sign-in context and IP correlation"
  - query: "AADServicePrincipalSignInLogs | take 1"
    description: "For service principal-based enumeration"
---

# Excessive User/Group Enumeration - Investigation Runbook

> **RB-0020** | Severity: High | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** MicrosoftGraphActivityLogs + AuditLogs Analysis
> **Detection Logic:** High-volume directory read operations via Graph API or Entra ID
> **Primary MITRE Technique:** T1087.004 - Account Discovery: Cloud Account

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Graph API Enumeration Detection](#step-1-graph-api-enumeration-detection)
   - [Step 2: Actor Identity and Sign-In Context](#step-2-actor-identity-and-sign-in-context)
   - [Step 3: Enumeration Target Analysis](#step-3-enumeration-target-analysis)
   - [Step 4: Baseline Comparison - Establish Normal Directory Query Pattern](#step-4-baseline-comparison---establish-normal-directory-query-pattern)
   - [Step 5: Service Principal Enumeration Detection](#step-5-service-principal-enumeration-detection)
   - [Step 6: Post-Enumeration Lateral Movement and Privilege Escalation](#step-6-post-enumeration-lateral-movement-and-privilege-escalation)
   - [Step 7: Organization-Wide Enumeration Activity Sweep](#step-7-organization-wide-enumeration-activity-sweep)
   - [Step 8: UEBA Enrichment — Behavioral Context Analysis](#step-8-ueba-enrichment--behavioral-context-analysis)
6. [Containment Playbook](#6-containment-playbook)
7. [Evidence Collection Checklist](#7-evidence-collection-checklist)
8. [Escalation Criteria](#8-escalation-criteria)
9. [False Positive Documentation](#9-false-positive-documentation)
10. [MITRE ATT&CK Mapping](#10-mitre-attck-mapping)
11. [Query Summary](#11-query-summary)
12. [Appendix A: Datatable Tests](#appendix-a-datatable-tests)
13. [References](#references)

---

## 1. Alert Context

**What triggers this alert:**
This detection fires when a user or service principal makes an unusually high volume of directory read requests in a short time window. The detection sources are:

1. **MicrosoftGraphActivityLogs:** Records every Graph API call, including the endpoint, HTTP method, and caller identity. Enumeration appears as rapid GET requests to `/users`, `/groups`, `/directoryRoles`, `/servicePrincipals`, and related endpoints.
2. **AuditLogs:** Records directory read operations that modify or access directory objects, though less granular than Graph logs.
3. **AADServicePrincipalSignInLogs:** Service principals (automated apps) making bulk directory queries — often the most dangerous vector.

Key enumeration patterns:
- **User enumeration:** Rapid calls to `/users`, `/users?$select=`, `/users/{id}` — listing all users in the directory
- **Group enumeration:** Calls to `/groups`, `/groups/{id}/members` — mapping organizational structure and security groups
- **Role enumeration:** Calls to `/directoryRoles`, `/directoryRoles/{id}/members` — identifying privileged accounts
- **Application enumeration:** Calls to `/servicePrincipals`, `/applications` — finding OAuth apps and their permissions
- **Membership chaining:** `/users/{id}/memberOf`, `/users/{id}/transitiveMemberOf` — mapping full access graph

**Why it matters:**
Directory enumeration is one of the first actions an attacker takes after gaining initial access. The goal is to understand the target environment:

- **Identify high-value targets:** Find Global Admins, finance team members, executives
- **Map security groups:** Understand which groups grant access to sensitive resources (VPN, production, finance)
- **Plan lateral movement:** Identify accounts with cross-domain trust or hybrid identities
- **Find weak accounts:** Discover service accounts, shared mailboxes, or accounts without MFA
- **Prepare for escalation:** Identify PIM-eligible roles and users who can grant admin access

Midnight Blizzard (APT29) used compromised OAuth apps to enumerate directories in the 2023-2024 Microsoft corporate attack. Scattered Spider aggressively enumerates directories to find IT and security team members for social engineering.

**Why this is HIGH severity:**
- Enumeration is a precursor to targeted attacks — the attacker is selecting their next victim
- Excessive enumeration from a regular user account indicates the account is compromised
- Service principal enumeration may indicate an OAuth app has been weaponized (see [RB-0011](consent-grant-attack.md))
- The data collected (user lists, group memberships, role assignments) is valuable for phishing, BEC, and social engineering

---

## 2. Prerequisites

{{ data_check_timeline(page.meta.data_checks) }}

---

## 3. Input Parameters

Set these values before running the investigation queries:

```kql
// === INVESTIGATION PARAMETERS ===
let InvestigationTarget = "user@company.com";   // UPN or ServicePrincipalId
let AlertTime = datetime(2026-02-22T14:30:00Z); // Time of enumeration detection
let LookbackWindow = 24h;                       // Analysis window
let BaselineWindow = 14d;                        // Historical baseline period
let EnumerationThreshold = 100;                   // Minimum API calls to flag
```

---

## 4. Quick Triage Criteria

Use this decision matrix for initial severity assessment:

| Indicator | True Positive Signal | False Positive Signal |
|---|---|---|
| Caller identity | Regular user, compromised app | Known HR/IT tool, People app |
| Volume | 500+ API calls in 1 hour | 10-50 calls spread over day |
| Endpoints | /directoryRoles, /users?$select=*, /groups | /me, /users/{specific-id} |
| Timing | Outside business hours, weekend | During business hours, predictable schedule |
| IP source | Hosting/VPS provider, new IP | Corporate network, known CI/CD |
| Post-enumeration | Privilege escalation, phishing, data access | No follow-up activity |

---

## 5. Investigation Steps

### Step 1: Graph API Enumeration Detection

**Objective:** Identify high-volume directory read operations via Microsoft Graph API, classify the enumeration targets, and quantify the data accessed.

```kql
// Step 1: Graph API Enumeration Detection
// Table: MicrosoftGraphActivityLogs | Detects high-volume directory enumeration
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
let EnumerationThreshold = 100;
// Directory enumeration endpoint patterns
let EnumerationEndpoints = dynamic([
    "/users", "/groups", "/directoryRoles", "/servicePrincipals",
    "/applications", "/directoryObjects", "/contacts",
    "/administrativeUnits", "/roleManagement"
]);
MicrosoftGraphActivityLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
| where RequestMethod == "GET"
| extend
    EndpointPath = tostring(split(RequestUri, "?")[0]),
    QueryParams = tostring(split(RequestUri, "?")[1])
| extend
    EndpointCategory = case(
        EndpointPath has "/users", "User Enumeration",
        EndpointPath has "/groups", "Group Enumeration",
        EndpointPath has "/directoryRoles", "Role Enumeration",
        EndpointPath has "/servicePrincipals", "Service Principal Enumeration",
        EndpointPath has "/applications", "Application Enumeration",
        EndpointPath has "/memberOf" or EndpointPath has "/members", "Membership Enumeration",
        EndpointPath has "/directoryObjects", "Directory Object Enumeration",
        EndpointPath has "/roleManagement", "Role Management Enumeration",
        "Other"
    )
| where EndpointCategory != "Other"
| summarize
    TotalCalls = count(),
    DistinctEndpoints = dcount(EndpointPath),
    EndpointCategories = make_set(EndpointCategory),
    SampleEndpoints = make_set(EndpointPath, 20),
    FirstCall = min(TimeGenerated),
    LastCall = max(TimeGenerated),
    SourceIPs = make_set(IPAddress, 10),
    ResponseCodes = make_set(ResponseStatusCode, 10),
    HasSelectAll = countif(QueryParams has "$select" or QueryParams has "$expand"),
    HasTopFilter = countif(QueryParams has "$top=999" or QueryParams has "$top=100")
    by UserId, AppId, ServicePrincipalId = tostring(ServicePrincipalId)
| where TotalCalls >= EnumerationThreshold
| extend
    EnumerationDuration = datetime_diff('minute', LastCall, FirstCall),
    CallsPerMinute = round(toreal(TotalCalls) / max_of(datetime_diff('minute', LastCall, FirstCall), 1), 1),
    EnumerationScope = case(
        array_length(EndpointCategories) >= 4, "BROAD - Multi-category reconnaissance",
        array_length(EndpointCategories) >= 2, "TARGETED - Multi-type enumeration",
        "FOCUSED - Single-type enumeration"
    ),
    CallerType = case(
        isnotempty(UserId) and isempty(ServicePrincipalId), "User",
        isnotempty(ServicePrincipalId), "Service Principal",
        "Unknown"
    )
| sort by TotalCalls desc
```

**What to look for:**

- **TotalCalls > 500** in a single session = aggressive automated enumeration
- **CallsPerMinute > 10** = programmatic access, not human browsing
- **EnumerationScope = "BROAD"** = attacker mapping the entire directory (users + groups + roles + apps)
- **EndpointCategories containing "Role Enumeration"** = attacker specifically looking for privileged accounts
- **HasTopFilter > 0** = using `$top=999` to maximize data per request — hallmark of enumeration tools
- **CallerType = "Service Principal"** = OAuth app being used for enumeration (see [RB-0011](consent-grant-attack.md))

#### Query 1B: Azure Portal / PowerShell Bulk User Export Detection

```kql
// Step 1B: Bulk User Export Detection via Azure Portal or PowerShell
// Table: AuditLogs | Detects bulk directory data export operations
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
AuditLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
| where OperationName in (
    "Download Users",
    "Export users",
    "Bulk download users",
    "Export group members",
    "Download group members",
    "Get user",
    "List users"
)
    or (Category == "UserManagement"
        and OperationName has_any ("Export", "Download", "Bulk"))
| extend
    ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
    ActorIP = tostring(InitiatedBy.user.ipAddress),
    ActorApp = tostring(InitiatedBy.app.displayName),
    TargetResource = tostring(TargetResources[0].displayName)
| project
    TimeGenerated,
    OperationName,
    ActorUPN,
    ActorIP,
    ActorApp,
    TargetResource,
    Result,
    ExportMethod = case(
        ActorApp has "Azure Portal", "Azure Portal (UI Download)",
        ActorApp has "Graph" or ActorApp has "PowerShell", "PowerShell / Graph API",
        ActorApp has "Azure CLI", "Azure CLI",
        isnotempty(ActorApp), strcat("App: ", ActorApp),
        "Unknown"
    ),
    ExportRisk = case(
        OperationName has_any ("Download", "Export", "Bulk"),
            "HIGH - Explicit bulk data export operation",
        OperationName == "List users" and Result == "success",
            "MEDIUM - User listing (may be programmatic export)",
        "LOW"
    )
| where ExportRisk != "LOW"
| sort by TimeGenerated asc
```

**What to look for:**

- **"Download Users" from Azure Portal** = User clicked the "Download users" button in the Entra ID portal — exports ALL users to CSV including UPN, display name, job title, department
- **ExportMethod = "PowerShell / Graph API"** = Programmatic export via `Get-MgUser -All` or `Export-Csv` — higher risk because it can include more fields than portal export
- **Multiple export operations in short succession** = Exporting users, groups, AND members separately — comprehensive directory data harvesting
- **ActorIP from hosting/VPS** = Export from non-corporate infrastructure — strong compromise indicator
- If this query returns results, correlate the actor with Step 2 sign-in context and Step 1 Graph API enumeration

---

### Step 2: Actor Identity and Sign-In Context

**Objective:** Identify who is performing the enumeration and from where, correlating Graph API activity with sign-in context.

```kql
// Step 2: Actor Identity and Sign-In Context
// Table: SigninLogs + MicrosoftGraphActivityLogs | Correlates enumeration with sign-in
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
// Get the IPs used for enumeration
let EnumerationIPs = MicrosoftGraphActivityLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where UserId has InvestigationTarget or
        ServicePrincipalId has InvestigationTarget
    | where RequestMethod == "GET"
    | distinct IPAddress;
// Get sign-in context for those IPs
SigninLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
| where UserPrincipalName =~ InvestigationTarget or IPAddress in (EnumerationIPs)
| extend ParsedLocation = parse_json(LocationDetails)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AutonomousSystemNumber,
    Country = tostring(ParsedLocation.countryOrRegion),
    City = tostring(ParsedLocation.city),
    UserAgent,
    AppDisplayName,
    ResourceDisplayName,
    ResultType,
    RiskLevelDuringSignIn,
    ConditionalAccessStatus,
    AuthenticationRequirement
| extend
    IsHostingIP = AutonomousSystemNumber in (HostingASNs),
    AuthResult = case(
        ResultType == "0", "Success",
        ResultType == "50126", "Wrong Password",
        strcat("Error: ", ResultType)
    )
| sort by TimeGenerated asc
```

**What to look for:**

- **IsHostingIP = true** = enumeration from VPS/hosting infrastructure — strong attacker indicator
- **AppDisplayName = "Microsoft Graph PowerShell"** or **"Azure CLI"** = command-line tooling, not browser-based
- **AppDisplayName** containing unknown/suspicious app name = potentially a rogue OAuth app
- **RiskLevelDuringSignIn** = did Identity Protection flag the session used for enumeration?
- **Multiple sign-ins from different IPs** to the same app = possible distributed enumeration
- **UserAgent** containing `python`, `Go-http-client`, `PowerShell` = automated enumeration tools

---

### Step 3: Enumeration Target Analysis

**Objective:** Analyze which specific directory objects were queried to understand what information the attacker collected.

```kql
// Step 3: Enumeration Target Analysis
// Table: MicrosoftGraphActivityLogs | Analyzes specific enumeration targets
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
MicrosoftGraphActivityLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
| where UserId has InvestigationTarget or
    ServicePrincipalId has InvestigationTarget
| where RequestMethod == "GET"
| extend
    EndpointPath = tostring(split(RequestUri, "?")[0]),
    QueryParams = tostring(split(RequestUri, "?")[1])
| extend
    // Detect if querying specific entities or listing all
    IsListOperation = iff(
        EndpointPath matches regex @"/v1\.0/(users|groups|directoryRoles|servicePrincipals|applications)$"
        or EndpointPath matches regex @"/beta/(users|groups|directoryRoles|servicePrincipals|applications)$",
        true, false
    ),
    // Detect membership queries
    IsMembershipQuery = iff(
        EndpointPath has "/members" or EndpointPath has "/memberOf"
        or EndpointPath has "/transitiveMemberOf",
        true, false
    ),
    // Detect sensitive field selection
    HasSensitiveFields = iff(
        QueryParams has_any ("passwordProfile", "passwordPolicies",
            "onPremisesSyncEnabled", "assignedLicenses", "assignedPlans",
            "securityIdentifier", "proxyAddresses"),
        true, false
    ),
    TargetCategory = case(
        EndpointPath has "/directoryRoles", "Privileged Roles",
        EndpointPath has "/groups" and EndpointPath has "/members", "Group Membership",
        EndpointPath has "/users" and (EndpointPath has "/memberOf" or EndpointPath has "/transitiveMemberOf"),
            "User Group Memberships",
        EndpointPath has "/servicePrincipals", "Applications/Service Principals",
        EndpointPath has "/users", "User Directory",
        EndpointPath has "/groups", "Group Directory",
        "Other Directory Objects"
    )
| summarize
    QueryCount = count(),
    ListOperations = countif(IsListOperation),
    MembershipQueries = countif(IsMembershipQuery),
    SensitiveFieldQueries = countif(HasSensitiveFields),
    SuccessfulQueries = countif(ResponseStatusCode between (200 .. 299)),
    FailedQueries = countif(ResponseStatusCode >= 400),
    SampleEndpoints = make_set(EndpointPath, 15),
    SampleParams = make_set(QueryParams, 10)
    by TargetCategory
| extend
    DataExposureRisk = case(
        TargetCategory == "Privileged Roles" and QueryCount > 10,
            "CRITICAL - Enumerating admin roles and members",
        SensitiveFieldQueries > 0,
            "HIGH - Querying sensitive user attributes",
        MembershipQueries > 20,
            "HIGH - Mass membership enumeration",
        ListOperations > 50,
            "MEDIUM - Bulk directory listing",
        "LOW"
    )
| sort by case(
    DataExposureRisk has "CRITICAL", 1,
    DataExposureRisk has "HIGH", 2,
    DataExposureRisk has "MEDIUM", 3,
    4
) asc
```

**What to look for:**

- **"CRITICAL - Enumerating admin roles and members"** = attacker specifically identifying Global Admins and privileged accounts
- **"HIGH - Querying sensitive user attributes"** = requesting password policies, sync status, or security IDs — advanced reconnaissance
- **"HIGH - Mass membership enumeration"** = mapping who belongs to which security groups — planning lateral movement
- **ListOperations > 50** = bulk listing entire directories — data harvesting
- **FailedQueries > 0** = some queries returned 403/404 — attacker's permissions are limited but they're trying
- **SampleParams containing "$expand"** = expanding related entities in a single call — efficient data extraction

---

### Step 4: Baseline Comparison - Establish Normal Directory Query Pattern

**Objective:** Compare the current enumeration volume against the entity's historical Graph API usage to determine if it's truly anomalous.

```kql
// Step 4: Baseline Comparison - Establish Normal Directory Query Pattern
// Table: MicrosoftGraphActivityLogs | Compares against 14-day historical baseline
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
let BaselineWindow = 14d;
let CurrentWindow = 24h;
// Define directory-related endpoints
let DirectoryEndpoints = dynamic([
    "/users", "/groups", "/directoryRoles", "/servicePrincipals",
    "/applications", "/directoryObjects", "/memberOf", "/members"
]);
// Historical baseline
let HistoricalPattern = MicrosoftGraphActivityLogs
    | where TimeGenerated between ((AlertTime - BaselineWindow) .. (AlertTime - CurrentWindow))
    | where UserId has InvestigationTarget or
        ServicePrincipalId has InvestigationTarget
    | where RequestMethod == "GET"
    | where RequestUri has_any (DirectoryEndpoints)
    | summarize
        BaselineTotalCalls = count(),
        BaselineDays = datetime_diff('day', max(TimeGenerated), min(TimeGenerated)),
        BaselineDistinctEndpoints = dcount(tostring(split(RequestUri, "?")[0])),
        BaselineDistinctDays = dcount(bin(TimeGenerated, 1d)),
        BaselineMaxCallsPerDay = max(count_per_day)
            by placeholder = 1
    | join kind=inner (
        MicrosoftGraphActivityLogs
        | where TimeGenerated between ((AlertTime - BaselineWindow) .. (AlertTime - CurrentWindow))
        | where UserId has InvestigationTarget or
            ServicePrincipalId has InvestigationTarget
        | where RequestMethod == "GET"
        | where RequestUri has_any (DirectoryEndpoints)
        | summarize count_per_day = count() by bin(TimeGenerated, 1d)
        | summarize
            BaselineAvgCallsPerDay = round(avg(count_per_day), 1),
            BaselineMaxCallsPerDay = max(count_per_day),
            BaselineStdev = round(stdev(count_per_day), 1)
        | extend placeholder = 1
    ) on placeholder
    | project-away placeholder, placeholder1;
// Current window
let CurrentPattern = MicrosoftGraphActivityLogs
    | where TimeGenerated between ((AlertTime - CurrentWindow) .. (AlertTime + 4h))
    | where UserId has InvestigationTarget or
        ServicePrincipalId has InvestigationTarget
    | where RequestMethod == "GET"
    | where RequestUri has_any (DirectoryEndpoints)
    | summarize
        CurrentTotalCalls = count(),
        CurrentDistinctEndpoints = dcount(tostring(split(RequestUri, "?")[0]));
HistoricalPattern
| extend p = 1
| join kind=fullouter (CurrentPattern | extend p = 1) on p
| project-away p, p1
| extend
    SpikeMultiplier = round(
        iff(coalesce(BaselineAvgCallsPerDay, 0) > 0,
            toreal(coalesce(CurrentTotalCalls, 0)) / BaselineAvgCallsPerDay,
            999.0), 1
    ),
    StandardDeviationsAbove = round(
        iff(coalesce(BaselineStdev, 0) > 0,
            (toreal(coalesce(CurrentTotalCalls, 0)) - coalesce(BaselineAvgCallsPerDay, 0)) / BaselineStdev,
            999.0), 1
    ),
    AnomalyVerdict = case(
        coalesce(BaselineTotalCalls, 0) == 0 and coalesce(CurrentTotalCalls, 0) > 0,
            "HIGH ANOMALY - First-ever directory enumeration activity",
        coalesce(CurrentTotalCalls, 0) > coalesce(BaselineMaxCallsPerDay, 0) * 5,
            "HIGH ANOMALY - Volume exceeds 5x historical maximum",
        coalesce(CurrentTotalCalls, 0) > coalesce(BaselineAvgCallsPerDay, 0) * 3,
            "MODERATE ANOMALY - Volume exceeds 3x daily average",
        coalesce(CurrentDistinctEndpoints, 0) > coalesce(BaselineDistinctEndpoints, 0) * 2,
            "MODERATE ANOMALY - Querying many new endpoint types",
        "LOW ANOMALY - Within historical range"
    )
```

**What to look for:**

- **"First-ever directory enumeration activity"** = This entity has never queried directory endpoints before — very suspicious
- **SpikeMultiplier > 5** = 5x above normal daily volume — strong anomaly signal
- **StandardDeviationsAbove > 3** = Statistically significant spike beyond normal variance
- **"Querying many new endpoint types"** = Usually queries /users, now also querying /directoryRoles, /groups — expanded reconnaissance
- **"LOW ANOMALY"** = Entity regularly makes these calls (HR app, sync tool) — likely false positive

---

### Step 5: Service Principal Enumeration Detection

**Objective:** Specifically check for service principals (automated apps) performing directory enumeration, which is often more dangerous than user-based enumeration.

```kql
// Step 5: Service Principal Enumeration Detection
// Table: AADServicePrincipalSignInLogs + MicrosoftGraphActivityLogs | Detects app-based enumeration
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 24h;
let DirectoryEndpoints = dynamic([
    "/users", "/groups", "/directoryRoles", "/servicePrincipals",
    "/applications", "/memberOf", "/members"
]);
// Service principals making Graph API directory calls
let SPGraphActivity = MicrosoftGraphActivityLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | where isnotempty(ServicePrincipalId)
    | where RequestMethod == "GET"
    | where RequestUri has_any (DirectoryEndpoints)
    | summarize
        GraphCalls = count(),
        EndpointTypes = make_set(
            case(
                RequestUri has "/users", "Users",
                RequestUri has "/groups", "Groups",
                RequestUri has "/directoryRoles", "Roles",
                RequestUri has "/servicePrincipals", "Apps",
                "Other"
            ), 10
        ),
        SourceIPs = make_set(IPAddress, 10),
        FirstCall = min(TimeGenerated),
        LastCall = max(TimeGenerated)
        by ServicePrincipalId, AppId;
// Enrich with sign-in context
let SPSignIns = AADServicePrincipalSignInLogs
    | where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
    | summarize
        SignInCount = count(),
        DistinctIPs = dcount(IPAddress),
        Countries = make_set(
            tostring(parse_json(LocationDetails).countryOrRegion), 5
        ),
        ResourceNames = make_set(ResourceDisplayName, 10)
        by ServicePrincipalId, ServicePrincipalName, AppId;
SPGraphActivity
| join kind=leftouter SPSignIns on ServicePrincipalId, AppId
| extend
    AppName = coalesce(ServicePrincipalName, strcat("AppId:", AppId)),
    EnumerationDuration = datetime_diff('minute', LastCall, FirstCall),
    RiskLevel = case(
        GraphCalls > 500 and array_length(EndpointTypes) >= 3,
            "CRITICAL - High-volume multi-type enumeration",
        GraphCalls > 200,
            "HIGH - Aggressive enumeration",
        GraphCalls > 50 and array_length(EndpointTypes) >= 2,
            "MEDIUM - Moderate enumeration",
        "LOW"
    )
| where RiskLevel != "LOW"
| project
    ServicePrincipalId,
    AppName,
    GraphCalls,
    EndpointTypes,
    SourceIPs,
    Countries,
    EnumerationDuration,
    RiskLevel,
    ResourceNames
| sort by GraphCalls desc
```

**What to look for:**

- **Unknown AppName** = App not recognized by the organization — potentially a rogue OAuth app (see [RB-0011](consent-grant-attack.md))
- **GraphCalls > 500** = Very aggressive enumeration from a single app
- **EndpointTypes containing "Roles"** = App specifically enumerating privileged role memberships — targeting admins
- **SourceIPs from hosting/VPS** = App running from attacker infrastructure
- **Countries not matching app's expected deployment region** = App being abused from a foreign location
- **Multiple apps with similar patterns** = Attacker using multiple OAuth apps for distributed enumeration

---

### Step 6: Post-Enumeration Lateral Movement and Privilege Escalation

**Objective:** Check if the enumeration was followed by targeted actions against the discovered high-value accounts, indicating the attacker is acting on the intelligence gathered.

```kql
// Step 6: Post-Enumeration Lateral Movement and Privilege Escalation
// Table: AuditLogs + SigninLogs | Detects actions taken after directory enumeration
let InvestigationTarget = "user@company.com";
let AlertTime = datetime(2026-02-22T14:30:00Z);
// Get the enumeration time window
let EnumerationEnd = toscalar(
    MicrosoftGraphActivityLogs
    | where TimeGenerated between ((AlertTime - 24h) .. (AlertTime + 4h))
    | where UserId has InvestigationTarget or
        ServicePrincipalId has InvestigationTarget
    | where RequestMethod == "GET"
    | summarize max(TimeGenerated)
);
// Post-enumeration audit actions (targeting discovered accounts)
let PostEnumActions = AuditLogs
    | where TimeGenerated between (EnumerationEnd .. (EnumerationEnd + 48h))
    | where InitiatedBy has InvestigationTarget
    | where OperationName in (
        // Privilege escalation
        "Add member to role", "Add eligible member to role",
        "Add member to group", "Add owner to group",
        // Credential manipulation
        "Add service principal credentials", "Update application – Certificates and secrets management",
        "Reset password", "Update user",
        // Persistence
        "Register security info", "Consent to application",
        "Add OAuth2PermissionGrant", "Add delegated permission grant",
        // Email manipulation
        "Set inbox rule", "New-InboxRule",
        // Policy changes
        "Update conditional access policy"
    )
    | project
        TimeGenerated,
        ActionCategory = case(
            OperationName has_any ("role", "Role"), "PRIVILEGE_ESCALATION",
            OperationName has_any ("group", "Group", "owner"), "GROUP_MANIPULATION",
            OperationName has_any ("credential", "secret", "certificate"), "CREDENTIAL_THEFT",
            OperationName has_any ("password", "Password"), "ACCOUNT_MANIPULATION",
            OperationName has_any ("Consent", "OAuth", "permission"), "APP_ABUSE",
            OperationName has_any ("inbox", "rule"), "EMAIL_COMPROMISE",
            OperationName has_any ("security info"), "MFA_MANIPULATION",
            "OTHER"
        ),
        OperationName,
        TargetResource = tostring(TargetResources[0].displayName),
        InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
        Result,
        HoursAfterEnum = round(datetime_diff('minute', TimeGenerated, EnumerationEnd) / 60.0, 1);
// Post-enumeration sign-ins to new resources
let PostEnumAccess = SigninLogs
    | where TimeGenerated between (EnumerationEnd .. (EnumerationEnd + 48h))
    | where UserPrincipalName =~ InvestigationTarget
    | where ResultType == "0"
    | where AppDisplayName !in ("Microsoft Graph", "Graph Explorer", "Azure Active Directory PowerShell")
    | project
        TimeGenerated,
        ActionCategory = "RESOURCE_ACCESS",
        OperationName = strcat("Sign-in to ", AppDisplayName),
        TargetResource = ResourceDisplayName,
        InitiatedByIP = IPAddress,
        Result = "success",
        HoursAfterEnum = round(datetime_diff('minute', TimeGenerated, EnumerationEnd) / 60.0, 1);
union PostEnumActions, PostEnumAccess
| extend
    SuspicionLevel = case(
        ActionCategory == "PRIVILEGE_ESCALATION", "CRITICAL - Role/group change after enumeration",
        ActionCategory == "CREDENTIAL_THEFT", "CRITICAL - Credential manipulation after enumeration",
        ActionCategory == "APP_ABUSE", "HIGH - OAuth app abuse after enumeration",
        ActionCategory == "EMAIL_COMPROMISE", "HIGH - Email rule after enumeration",
        ActionCategory == "MFA_MANIPULATION", "HIGH - MFA change after enumeration",
        "MEDIUM"
    )
| sort by TimeGenerated asc
```

**What to look for:**

- **PRIVILEGE_ESCALATION within hours of enumeration** = Attacker found admin accounts via enumeration, now escalating (see [RB-0013](privileged-role-assignment.md))
- **CREDENTIAL_THEFT** = Adding secrets to service principals discovered during enumeration
- **EMAIL_COMPROMISE shortly after enumeration** = BEC targeting specific users identified during recon
- **HoursAfterEnum < 4** = Rapid follow-up — automated or well-prepared attacker
- **TargetResource matching accounts/groups discovered in enumeration** = Direct correlation between recon and attack

---

### Step 7: Organization-Wide Enumeration Activity Sweep

**Objective:** Find all entities performing unusual directory enumeration across the organization to identify coordinated campaigns.

```kql
// Step 7: Organization-Wide Enumeration Activity Sweep
// Table: MicrosoftGraphActivityLogs | Finds all high-volume directory enumeration org-wide
let AlertTime = datetime(2026-02-22T14:30:00Z);
let LookbackWindow = 7d;
let EnumerationThreshold = 100;
let DirectoryEndpoints = dynamic([
    "/users", "/groups", "/directoryRoles", "/servicePrincipals",
    "/applications", "/memberOf", "/members"
]);
let HostingASNs = dynamic([14061, 16509, 14618, 15169, 396982, 8075, 13335, 24940,
    16276, 63949, 20473, 46606, 36352, 55286, 51167, 9009]);
MicrosoftGraphActivityLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. AlertTime)
| where RequestMethod == "GET"
| where RequestUri has_any (DirectoryEndpoints)
| summarize
    TotalCalls = count(),
    DistinctEndpoints = dcount(tostring(split(RequestUri, "?")[0])),
    EndpointTypes = make_set(
        case(
            RequestUri has "/directoryRoles", "Roles",
            RequestUri has "/users", "Users",
            RequestUri has "/groups", "Groups",
            RequestUri has "/servicePrincipals", "Apps",
            "Other"
        ), 10
    ),
    SourceIPs = make_set(IPAddress, 10),
    SourceASNs = make_set(toint(IPAddress), 5),  // Note: ASN may need separate enrichment
    ActiveDays = dcount(bin(TimeGenerated, 1d)),
    FirstCall = min(TimeGenerated),
    LastCall = max(TimeGenerated)
    by
        CallerIdentity = coalesce(UserId, ServicePrincipalId),
        CallerType = iff(isnotempty(UserId), "User", "ServicePrincipal"),
        AppId
| where TotalCalls >= EnumerationThreshold
| extend
    AvgCallsPerDay = round(toreal(TotalCalls) / max_of(ActiveDays, 1), 1),
    RiskScore = 0
        + iff(TotalCalls > 1000, 30, iff(TotalCalls > 500, 20, 10))
        + iff(array_length(EndpointTypes) >= 3, 25, iff(array_length(EndpointTypes) >= 2, 15, 5))
        + iff(set_has_element(EndpointTypes, "Roles"), 20, 0)
        + iff(CallerType == "User", 15, 0)  // Users enumerating is more suspicious than apps
        + iff(ActiveDays == 1, 10, 0),       // All activity in single day = burst
    RiskVerdict = case(
        TotalCalls > 1000 and set_has_element(EndpointTypes, "Roles"),
            "CRITICAL - Mass enumeration including privileged roles",
        TotalCalls > 500 and array_length(EndpointTypes) >= 3,
            "HIGH - Aggressive multi-type enumeration",
        CallerType == "User" and TotalCalls > 200,
            "HIGH - User-based mass enumeration",
        TotalCalls > 100 and ActiveDays == 1,
            "MEDIUM - Burst enumeration activity",
        "LOW - Elevated but within thresholds"
    )
| where RiskScore >= 40
| sort by RiskScore desc, TotalCalls desc
```

**What to look for:**

- **RiskVerdict = "CRITICAL"** = Entity performing mass enumeration including role discovery — active recon
- **Multiple CallerIdentities with "HIGH" risk in same time window** = Coordinated enumeration campaign
- **User-based enumeration with 200+ calls** = Compromised user account being used for recon
- **Same AppId across multiple CallerIdentities** = Single rogue app used by multiple compromised identities
- **ActiveDays == 1 with high volume** = Single-day burst — smash-and-grab reconnaissance

---

### Step 8: UEBA Enrichment — Behavioral Context Analysis

**Purpose:** Leverage Microsoft Sentinel's UEBA engine to assess whether the enumerating entity has a history of anomalous behavior. UEBA's `ActivityInsights` fields reveal if the account suddenly started querying directory objects it never accessed before, using unfamiliar tools from new locations — critical context for distinguishing a compromised account performing reconnaissance from a legitimate IT automation.

!!! info "Requires Sentinel UEBA"
    This step requires [Microsoft Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics) to be enabled. If UEBA is not configured in your environment, skip this step. The investigation remains valid without UEBA, but behavioral context significantly improves confidence in True/False Positive determination.

#### Query 8A: Enumerating Entity — UEBA Behavioral Assessment

```kql
// Step 8A: UEBA Behavioral Assessment for Enumerating Entity
// Table: BehaviorAnalytics | Checks behavioral anomalies during enumeration window
let AlertTime = datetime(2026-02-22T14:30:00Z);
let TargetUser = "user@company.com";
let LookbackWindow = 7d;
BehaviorAnalytics
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 1d))
| where UserPrincipalName =~ TargetUser
| project
    TimeGenerated,
    UserPrincipalName,
    ActivityType,
    ActionType,
    InvestigationPriority,
    SourceIPAddress,
    SourceIPLocation,
    // Activity anomaly indicators
    ActivityInsights = parse_json(ActivityInsights),
    UsersInsights = parse_json(UsersInsights)
| extend
    // Directory / app access anomalies
    FirstTimeAppUsed = tostring(ActivityInsights.FirstTimeUserUsedApp),
    AppUncommonlyUsed = tostring(ActivityInsights.AppUncommonlyUsedByUser),
    AppUncommonAmongPeers = tostring(ActivityInsights.AppUncommonlyUsedAmongPeers),
    FirstTimeActionPerformed = tostring(ActivityInsights.FirstTimeUserPerformedAction),
    ActionUncommonlyPerformed = tostring(ActivityInsights.ActionUncommonlyPerformedByUser),
    ActionUncommonAmongPeers = tostring(ActivityInsights.ActionUncommonlyPerformedAmongPeers),
    // Location / device anomalies
    FirstTimeCountry = tostring(ActivityInsights.FirstTimeUserConnectedFromCountry),
    CountryUncommon = tostring(ActivityInsights.CountryUncommonlyConnectedFromByUser),
    FirstTimeDevice = tostring(ActivityInsights.FirstTimeUserUsedDevice),
    DeviceUncommon = tostring(ActivityInsights.DeviceUncommonlyUsedByUser),
    FirstTimeISP = tostring(ActivityInsights.FirstTimeUserConnectedViaISP),
    ISPUncommon = tostring(ActivityInsights.ISPUncommonlyUsedByUser),
    // Volume anomalies
    UncommonHighVolume = tostring(ActivityInsights.UncommonHighVolumeOfActions),
    // User profile
    BlastRadius = tostring(UsersInsights.BlastRadius),
    IsDormantAccount = tostring(UsersInsights.IsDormantAccount),
    IsNewAccount = tostring(UsersInsights.IsNewAccount)
| extend
    AnomalySignals = array_length(
        pack_array(
            iff(FirstTimeAppUsed == "True", "FirstTimeApp", ""),
            iff(AppUncommonlyUsed == "True", "UncommonApp", ""),
            iff(FirstTimeActionPerformed == "True", "FirstTimeAction", ""),
            iff(ActionUncommonlyPerformed == "True", "UncommonAction", ""),
            iff(FirstTimeCountry == "True", "FirstTimeCountry", ""),
            iff(CountryUncommon == "True", "UncommonCountry", ""),
            iff(FirstTimeDevice == "True", "FirstTimeDevice", ""),
            iff(FirstTimeISP == "True", "FirstTimeISP", ""),
            iff(UncommonHighVolume == "True", "HighVolume", ""),
            iff(IsDormantAccount == "True", "DormantAccount", "")
        )
    )
| order by InvestigationPriority desc, TimeGenerated desc
```

**Expected findings:**

| Indicator | Malicious Signal | Benign Signal |
|---|---|---|
| InvestigationPriority >= 7 | Highly anomalous activity — UEBA engine flags significant deviation | Normal account behavior |
| FirstTimeAppUsed = True | Account suddenly using Graph PowerShell / CLI for the first time | IT admin regularly uses graph tools |
| UncommonHighVolume = True | Burst of activity unlike historical pattern — enumeration spike | HR sync app with consistent daily volume |
| FirstTimeActionPerformed = True | Account never performed directory reads before — new capability | IT role routinely reads directory |
| IsDormantAccount = True | Dormant account reactivated for enumeration — strong compromise signal | Seasonal user (contractor returning) |
| FirstTimeCountry = True | Enumeration from a country never seen for this account | User traveling to new location |
| BlastRadius = High | Compromised account has wide access — high impact potential | Expected for IT admin accounts |

**Decision guidance:**

- **InvestigationPriority >= 7** with **UncommonHighVolume = True** + **FirstTimeAppUsed = True** → Strong indicator of compromised account used for reconnaissance. Escalate immediately.
- **IsDormantAccount = True** + any enumeration activity → Dormant account reactivation for directory enumeration is a classic post-compromise pattern. Treat as confirmed compromise until proven otherwise.
- **FirstTimeActionPerformed = True** + **FirstTimeCountry = True** → New capability from a new location — multiple "firsts" dramatically increase confidence in True Positive.
- **InvestigationPriority < 4** with no anomaly flags → Account's enumeration pattern is consistent with historical behavior. Likely a legitimate tool or automation. Validate with app owner.

---

## 6. Containment Playbook

### Immediate Actions (0-30 minutes)
- [ ] **Block the caller:** If user account — revoke sessions and reset password. If service principal — disable the application
- [ ] **Review app permissions:** If service principal enumeration, audit the app's Microsoft Graph permissions (Directory.Read.All is the key one)
- [ ] **Block the source IPs** via Conditional Access Named Locations
- [ ] **Alert the security team:** Directory enumeration is a precursor to targeted attacks

### Short-term Actions (30 min - 4 hours)
- [ ] **Review what data was accessed:** Use Step 3 to understand what the attacker learned
- [ ] **Protect discovered targets:** If admin roles were enumerated, force MFA re-registration and session revocation for all admins
- [ ] **Revoke OAuth app consent** if a rogue app was performing the enumeration
- [ ] **Review application permissions:** Audit all apps with `Directory.Read.All` or `User.Read.All` scopes
- [ ] **Check for follow-up actions:** Run Step 6 to detect post-enumeration attacks

### Recovery Actions (4-24 hours)
- [ ] Implement Microsoft Graph API rate limiting and monitoring
- [ ] Deploy Conditional Access policy restricting Graph API access to managed devices
- [ ] Review and reduce Graph API permissions for all applications (principle of least privilege)
- [ ] Enable MicrosoftGraphActivityLogs diagnostic settings if not already configured
- [ ] Implement alerting rule for directory enumeration exceeding thresholds

---

## 7. Evidence Collection Checklist

| Evidence Item | Source Table | Retention | Collection Query |
|---|---|---|---|
| Graph API enumeration calls | MicrosoftGraphActivityLogs | 30 days | Step 1 query |
| Actor sign-in context | SigninLogs | 30 days | Step 2 query |
| Enumeration target analysis | MicrosoftGraphActivityLogs | 30 days | Step 3 query |
| Historical Graph API baseline | MicrosoftGraphActivityLogs | 30 days | Step 4 query |
| Service principal enumeration | AADServicePrincipalSignInLogs + Graph | 30 days | Step 5 query |
| Post-enumeration actions | AuditLogs + SigninLogs | 30 days | Step 6 query |
| Org-wide enumeration sweep | MicrosoftGraphActivityLogs | 30 days | Step 7 query |

---

## 8. Escalation Criteria

| Condition | Action |
|---|---|
| Enumeration of privileged roles + post-enum escalation (Steps 1, 6) | Escalate to **P1 Incident** — active attack chain |
| Service principal with Directory.Read.All performing mass enumeration | Escalate to **P1 Incident** — rogue app or compromised app |
| Multiple identities enumerating from same infrastructure (Step 7) | Escalate to **P1 Incident** — coordinated campaign |
| User account performing 500+ directory calls in a day | Escalate to **P2 Incident** — compromised user account |
| Enumeration from hosting/VPS IP (Step 2) | Escalate to **P2 Incident** — attacker infrastructure |
| Known HR/IT app with elevated activity | Escalate to **P3** — investigate but likely false positive |

---

## 9. False Positive Documentation

| Scenario | How to Identify | Recommended Action |
|---|---|---|
| HR/People application syncing directory | Known app, consistent pattern, documented integration | Add to allowlist, set higher threshold |
| Azure AD Connect / Cloud Sync | Sync service principal, regular cadence | Exclude from detection |
| IT admin using Graph Explorer | Admin role, Graph Explorer app, business hours | Verify purpose, document |
| CI/CD pipeline querying users | Known pipeline service principal, expected behavior | Whitelist specific AppId |
| Microsoft Teams/Outlook resolving contacts | Microsoft first-party app, low volume per user | Exclude first-party AppIds |
| Security tool (SIEM, SOAR) ingesting directory data | Known security vendor app, documented integration | Whitelist with monitoring |

---

## 10. MITRE ATT&CK Mapping

| Technique ID | Technique Name | How It Applies | Detection Query |
|---|---|---|---|
| T1087.004 | Account Discovery: Cloud Account | Enumerating Entra ID user directory | Steps 1, 3, 7 |
| T1069.003 | Permission Groups Discovery: Cloud Groups | Enumerating group memberships and security groups | Steps 1, 3 |
| T1087 | Account Discovery | General directory object enumeration | Steps 1, 4 |
| T1538 | Cloud Service Dashboard | Using Graph API as a cloud management interface | Steps 2, 5 |
| T1580 | Cloud Infrastructure Discovery | Mapping cloud identity infrastructure | Steps 3, 5 |

---

## 11. Query Summary

| Step | Query | Purpose | Primary Table |
|---|---|---|---|
| 1 | Graph API Enumeration Detection | Identify high-volume directory reads | MicrosoftGraphActivityLogs |
| 1B | Bulk User Export Detection | Detect Azure Portal/PowerShell bulk exports | AuditLogs |
| 2 | Actor Identity and Sign-In Context | Correlate enumeration with sign-in data | SigninLogs + GraphLogs |
| 3 | Enumeration Target Analysis | Analyze what directory objects were queried | MicrosoftGraphActivityLogs |
| 4 | Baseline Comparison | Compare against 14-day API usage history | MicrosoftGraphActivityLogs |
| 5 | Service Principal Enumeration | Detect app-based directory enumeration | AADServicePrincipalSignInLogs + GraphLogs |
| 6 | Post-Enumeration Actions | Find privilege escalation after recon | AuditLogs + SigninLogs |
| 7 | Org-Wide Enumeration Sweep | Find all high-volume enumerators | MicrosoftGraphActivityLogs |
| 8 | UEBA Behavioral Assessment | Behavioral anomaly context for enumerating entity | BehaviorAnalytics |

---

## Appendix A: Datatable Tests

### Test 1: High-Volume Graph API Enumeration Detection

```kql
// TEST 1: Verifies detection of high-volume directory enumeration
let EnumerationThreshold = 100;
let TestGraphLogs = datatable(
    TimeGenerated: datetime, UserId: string, ServicePrincipalId: string,
    AppId: string, RequestMethod: string, RequestUri: string,
    ResponseStatusCode: int, IPAddress: string
)[
    // User enumerating users (120 calls)
    datetime(2026-02-22T14:00:00Z), "alice@contoso.com", "", "app-001", "GET",
        "/v1.0/users?$top=999", 200, "198.51.100.50",
    datetime(2026-02-22T14:00:01Z), "alice@contoso.com", "", "app-001", "GET",
        "/v1.0/users?$top=999&$skiptoken=abc", 200, "198.51.100.50",
    datetime(2026-02-22T14:01:00Z), "alice@contoso.com", "", "app-001", "GET",
        "/v1.0/groups", 200, "198.51.100.50",
    datetime(2026-02-22T14:02:00Z), "alice@contoso.com", "", "app-001", "GET",
        "/v1.0/directoryRoles", 200, "198.51.100.50",
    // Normal user (5 calls)
    datetime(2026-02-22T14:00:00Z), "bob@contoso.com", "", "app-002", "GET",
        "/v1.0/me", 200, "10.0.0.100",
    datetime(2026-02-22T14:01:00Z), "bob@contoso.com", "", "app-002", "GET",
        "/v1.0/me/memberOf", 200, "10.0.0.100"
];
// Simulate 120 calls by aggregating with higher count
let SimulatedCounts = datatable(
    UserId: string, TotalCalls: long, EndpointCategories: dynamic
)[
    "alice@contoso.com", 120, dynamic(["User Enumeration", "Group Enumeration", "Role Enumeration"]),
    "bob@contoso.com", 5, dynamic(["Other"])
];
SimulatedCounts
| where TotalCalls >= EnumerationThreshold
| extend EnumerationScope = case(
    array_length(EndpointCategories) >= 3, "BROAD - Multi-category reconnaissance",
    array_length(EndpointCategories) >= 2, "TARGETED",
    "FOCUSED"
)
| where UserId == "alice@contoso.com" and EnumerationScope == "BROAD - Multi-category reconnaissance"
// EXPECTED: 1 row — alice with 120 calls across Users, Groups, and Roles
```

### Test 2: Service Principal Enumeration Detection

```kql
// TEST 2: Verifies detection of service principal performing directory enumeration
let TestSPActivity = datatable(
    ServicePrincipalId: string, AppName: string, GraphCalls: int,
    EndpointTypes: dynamic, SourceIPs: dynamic
)[
    // Rogue app - high volume enumeration
    "sp-malicious-001", "SuspiciousApp", 750,
        dynamic(["Users", "Groups", "Roles"]),
        dynamic(["198.51.100.50"]),
    // Legitimate HR app
    "sp-hr-sync", "Workday-Sync", 200,
        dynamic(["Users"]),
        dynamic(["10.0.0.50"]),
    // Normal app
    "sp-teams", "Microsoft Teams", 30,
        dynamic(["Users"]),
        dynamic(["10.0.0.60"])
];
TestSPActivity
| extend RiskLevel = case(
    GraphCalls > 500 and array_length(EndpointTypes) >= 3,
        "CRITICAL - High-volume multi-type enumeration",
    GraphCalls > 200,
        "HIGH - Aggressive enumeration",
    "LOW"
)
| where RiskLevel has "CRITICAL"
| where ServicePrincipalId == "sp-malicious-001"
// EXPECTED: 1 row — malicious SP with 750 calls across Users, Groups, Roles
```

### Test 3: Post-Enumeration Privilege Escalation Detection

```kql
// TEST 3: Verifies detection of privilege escalation after directory enumeration
let EnumerationEnd = datetime(2026-02-22T15:00:00Z);
let TestAuditLogs = datatable(
    TimeGenerated: datetime, OperationName: string, InitiatedBy: dynamic,
    TargetResources: dynamic, Result: string
)[
    // Role assignment 2 hours after enumeration
    datetime(2026-02-22T17:00:00Z), "Add member to role",
        dynamic({"user":{"userPrincipalName":"alice@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"Global Administrator"}]), "success",
    // Service principal credential addition
    datetime(2026-02-22T17:30:00Z), "Add service principal credentials",
        dynamic({"user":{"userPrincipalName":"alice@contoso.com","ipAddress":"198.51.100.50"}}),
        dynamic([{"displayName":"FinanceApp"}]), "success",
    // Normal operation (different user)
    datetime(2026-02-22T18:00:00Z), "Update user",
        dynamic({"user":{"userPrincipalName":"admin@contoso.com","ipAddress":"10.0.0.1"}}),
        dynamic([{"displayName":"bob@contoso.com"}]), "success"
];
let InvestigationTarget = "alice@contoso.com";
TestAuditLogs
| where TimeGenerated between (EnumerationEnd .. (EnumerationEnd + 48h))
| where InitiatedBy has InvestigationTarget
| extend ActionCategory = case(
    OperationName has_any ("role", "Role"), "PRIVILEGE_ESCALATION",
    OperationName has_any ("credential", "secret"), "CREDENTIAL_THEFT",
    "OTHER"
)
| where ActionCategory in ("PRIVILEGE_ESCALATION", "CREDENTIAL_THEFT")
| summarize
    PostEnumActions = count(),
    Categories = make_set(ActionCategory)
| where PostEnumActions == 2
    and set_has_element(Categories, "PRIVILEGE_ESCALATION")
    and set_has_element(Categories, "CREDENTIAL_THEFT")
// EXPECTED: 1 row — both privilege escalation and credential theft after enumeration
```

### Test 4: Org-Wide Enumeration Sweep

```kql
// TEST 4: Verifies detection of multiple entities performing enumeration org-wide
let EnumerationThreshold = 100;
let TestEnumeration = datatable(
    CallerIdentity: string, CallerType: string, AppId: string,
    TotalCalls: int, EndpointTypes: dynamic, ActiveDays: int
)[
    // Compromised user - burst enumeration
    "alice@contoso.com", "User", "graph-explorer", 350,
        dynamic(["Users", "Groups", "Roles"]), 1,
    // Rogue service principal
    "sp-malicious", "ServicePrincipal", "rogue-app", 800,
        dynamic(["Users", "Groups", "Roles", "Apps"]), 2,
    // Legitimate HR sync
    "sp-hr-sync", "ServicePrincipal", "hr-app", 150,
        dynamic(["Users"]), 7,
    // Normal user
    "bob@contoso.com", "User", "teams", 25,
        dynamic(["Users"]), 5
];
TestEnumeration
| where TotalCalls >= EnumerationThreshold
| extend
    RiskScore = 0
        + iff(TotalCalls > 500, 30, iff(TotalCalls > 200, 20, 10))
        + iff(array_length(EndpointTypes) >= 3, 25, 5)
        + iff(set_has_element(EndpointTypes, "Roles"), 20, 0)
        + iff(CallerType == "User", 15, 0)
        + iff(ActiveDays == 1, 10, 0)
| where RiskScore >= 40
| summarize HighRiskEnumerators = count(), Identities = make_set(CallerIdentity)
| where HighRiskEnumerators >= 2
// EXPECTED: 1 row — 2 high-risk enumerators (alice and sp-malicious)
```

---

## References

- [MicrosoftGraphActivityLogs - Microsoft Learn](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview)
- [Configure Microsoft Graph API logging](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-configure-microsoft-graph-activity-logs)
- [Microsoft Graph API permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [MITRE ATT&CK T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [MITRE ATT&CK T1069 - Permission Groups Discovery](https://attack.mitre.org/techniques/T1069/)
- [Midnight Blizzard OAuth app abuse for directory enumeration](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
- [Scattered Spider reconnaissance techniques](https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/)
