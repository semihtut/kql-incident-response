---
title: "Suspicious Inbox Forwarding Rule"
id: RB-0008
severity: high
status: reviewed
description: >
  Investigation runbook for suspicious inbox forwarding or redirect rules
  detected in Exchange Online via OfficeActivity logs and Defender for Cloud
  Apps alerts. Covers rule parameter analysis, sign-in context correlation,
  forwarded email volume assessment, and org-wide forwarding sweep. Inbox
  forwarding rules are a primary persistence and exfiltration mechanism in
  business email compromise (BEC) attacks — attackers create rules to silently
  copy or redirect mail to external addresses while hiding evidence by
  marking messages as read or moving them to obscure folders.
mitre_attack:
  tactics:
    - tactic_id: TA0009
      tactic_name: "Collection"
    - tactic_id: TA0010
      tactic_name: "Exfiltration"
    - tactic_id: TA0003
      tactic_name: "Persistence"
    - tactic_id: TA0005
      tactic_name: "Defense Evasion"
    - tactic_id: TA0001
      tactic_name: "Initial Access"
  techniques:
    - technique_id: T1114.003
      technique_name: "Email Collection: Email Forwarding Rule"
      confidence: confirmed
    - technique_id: T1564.008
      technique_name: "Hide Artifacts: Email Hiding Rules"
      confidence: confirmed
    - technique_id: T1114.002
      technique_name: "Email Collection: Remote Email Collection"
      confidence: probable
    - technique_id: T1078.004
      technique_name: "Valid Accounts: Cloud Accounts"
      confidence: confirmed
    - technique_id: T1534
      technique_name: "Internal Spearphishing"
      confidence: probable
    - technique_id: T1098.002
      technique_name: "Account Manipulation: Additional Email Delegate Permissions"
      confidence: probable
threat_actors:
  - "Scattered Spider (Octo Tempest)"
  - "Midnight Blizzard (APT29)"
  - "Peach Sandstorm (APT33)"
  - "Storm-0539 (Atlas Lion)"
  - "Volt Typhoon"
log_sources:
  - table: "OfficeActivity"
    product: "Office 365"
    license: "M365 E3+"
    required: true
    alternatives: []
  - table: "CloudAppEvents"
    product: "Defender for Cloud Apps"
    license: "M365 E5 / Defender for Cloud Apps"
    required: false
    alternatives: ["OfficeActivity"]
  - table: "EmailEvents"
    product: "Defender for Office 365"
    license: "MDO P2"
    required: false
    alternatives: []
  - table: "SigninLogs"
    product: "Entra ID"
    license: "Entra ID Free"
    required: true
    alternatives: []
  - table: "AuditLogs"
    product: "Entra ID"
    license: "Entra ID Free"
    required: true
    alternatives: []
  - table: "AADUserRiskEvents"
    product: "Entra ID Identity Protection"
    license: "Entra ID P2"
    required: false
    alternatives: []
author: "Leo (Coordinator), Arina (IR), Hasan (Platform), Samet (KQL), Yunus (TI), Alp (QA)"
created: 2026-02-22
updated: 2026-02-22
version: "1.0"
tier: 2
category: email
data_checks:
  - query: "OfficeActivity | take 1"
    label: primary
    description: "Inbox rule creation events"
  - query: "SigninLogs | take 1"
    description: "For sign-in context correlation"
  - query: "AuditLogs | take 1"
    description: "For other persistence detection"
  - query: "CloudAppEvents | take 1"
    label: optional
    description: "Defender for Cloud Apps enrichment"
  - query: "EmailEvents | take 1"
    label: optional
    description: "Forward email tracking (MDO P2 only)"
---

# Suspicious Inbox Forwarding Rule - Investigation Runbook

> **RB-0008** | Severity: High | Version: 1.0 | Last updated: 2026-02-22
>
> **Alert Source:** Microsoft Defender for Cloud Apps + Sentinel Analytics (OfficeActivity)
> **Detection Operations:** `New-InboxRule`, `Set-InboxRule`, `Set-Mailbox` with forwarding parameters
> **Primary MITRE Technique:** T1114.003 - Email Collection: Email Forwarding Rule

## Table of Contents

1. [Alert Context](#1-alert-context)
2. [Prerequisites](#2-prerequisites)
3. [Input Parameters](#3-input-parameters)
4. [Quick Triage Criteria](#4-quick-triage-criteria)
5. [Investigation Steps](#5-investigation-steps)
   - [Step 1: Extract Inbox Rule Creation Event](#step-1-extract-inbox-rule-creation-event)
   - [Step 2: Rule Parameter Deep Dive](#step-2-rule-parameter-deep-dive)
   - [Step 3: Sign-In Context Analysis](#step-3-sign-in-context-analysis)
   - [Step 4: Baseline Comparison - Establish Normal Rule Creation Pattern](#step-4-baseline-comparison---establish-normal-rule-creation-pattern)
   - [Step 5: Forwarded Email Volume Assessment](#step-5-forwarded-email-volume-assessment)
   - [Step 6: Cross-Reference with Persistence Mechanisms](#step-6-cross-reference-with-persistence-mechanisms)
   - [Step 7: Org-Wide Forwarding Rule Sweep](#step-7-org-wide-forwarding-rule-sweep)
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
Suspicious inbox forwarding rules are detected through three complementary mechanisms:

1. **OfficeActivity log analysis:** Sentinel analytics rules monitor for `New-InboxRule`, `Set-InboxRule`, and `Set-Mailbox` operations in the OfficeActivity table. Rules are flagged when parameters include `ForwardTo`, `ForwardAsAttachmentTo`, `RedirectTo` pointing to external domains, or when combined with `DeleteMessage` or `MarkAsRead` (evidence-hiding behavior).
2. **Defender for Cloud Apps policy:** The built-in "Suspicious inbox forwarding rule" alert fires when a user creates a rule that forwards all incoming email to an external address, particularly when paired with deletion of the original message.
3. **Exchange Online transport rule analysis:** Server-side forwarding configured via `Set-Mailbox -ForwardingSmtpAddress` or `Set-Mailbox -ForwardTo` bypasses client-side inbox rules entirely and is harder to detect without log monitoring.

**Why it matters:**
Inbox forwarding rules are the #1 persistence mechanism in business email compromise (BEC) attacks. After gaining access to a mailbox (via phishing, credential stuffing, or session hijacking), attackers immediately create forwarding rules to maintain visibility into all incoming email — even after the password is changed. This gives them ongoing access to financial communications, invoices, wire transfer requests, and sensitive business data. The FBI's IC3 reported over $2.9 billion in BEC losses in 2023 alone, and inbox forwarding rules are present in the majority of these cases.

**Why this is HIGH severity:**
- Forwarding rules persist even after password resets — the attacker continues receiving mail until the rule is discovered and removed
- Rules that combine forwarding with `DeleteMessage=true` or `MarkAsRead=true` actively hide evidence from the victim
- External forwarding enables real-time surveillance of financial conversations for invoice fraud timing
- A single forwarding rule can exfiltrate months of email before detection
- Attackers often create rules targeting specific keywords ("invoice", "wire", "payment", "bank") rather than forwarding all mail, making detection harder

**However:** This alert has a **moderate false positive rate** (~20-30%). Legitimate triggers include:
- Users forwarding work email to personal accounts during transitions or vacations
- IT administrators configuring shared mailbox forwarding for business workflows
- Automated forwarding to ticketing systems (ServiceNow, Jira, Zendesk)
- Compliance-required journaling rules forwarding to archive mailboxes
- Users setting up forwarding to new company email addresses during mergers/acquisitions

**Worst case scenario if this is real:**
An attacker has compromised a user's mailbox (via phishing, token theft, or credential stuffing) and created a silent forwarding rule that copies all email — or emails matching financial keywords — to an external address they control. The rule marks forwarded messages as read and moves originals to a hidden folder, so the victim never notices. The attacker monitors financial conversations for weeks, then executes a wire transfer fraud by injecting themselves into an email thread with modified banking details. Meanwhile, the rule persists even after the security team resets the user's password, because the rule is a mailbox-level setting, not session-dependent. If the compromised account belongs to a finance executive or accounts payable team member, the loss potential is in the millions.

**Key difference from other runbooks:**
- RB-0001 through RB-0006 focus on identity-based alerts (sign-in anomalies, credential attacks). The compromise detection is at the authentication layer.
- **RB-0008 (This runbook):** The investigation starts AFTER the attacker already has mailbox access. The focus is on **what they're doing with that access** — specifically, setting up email collection infrastructure. The critical question is: **"What does this rule forward, where does it send it, and has any mail already been exfiltrated?"** This is the first runbook where the primary data source is OfficeActivity (Exchange operations), not SigninLogs.

---

## 2. Prerequisites

### Minimum Required
- **License:** Microsoft 365 E3 + Microsoft Sentinel
- **Sentinel Connectors:** Office 365 (OfficeActivity)
- **Permissions:** Security Reader (investigation), Security Operator (containment), Exchange Online Administrator (rule removal)

### Recommended for Full Coverage
- **License:** Microsoft 365 E5 + Sentinel
- **Additional Connectors:** Microsoft Entra ID (SigninLogs), Defender for Cloud Apps (CloudAppEvents), Defender for Office 365 (EmailEvents)
- **Exchange Online:** Mailbox auditing enabled (on by default since 2019), admin audit logging enabled
- **Transport Rules:** External forwarding blocked or monitored via Exchange transport rules

### Data Availability Check

{{ data_check_timeline(page.meta.data_checks) }}

### Licensing Coverage by Investigation Step

| License Tier | Tables Available | Steps Covered |
|---|---|---|
| M365 E3 + Sentinel | OfficeActivity, SigninLogs, AuditLogs | Steps 1-4, 6-7 |
| M365 E5 + Sentinel | Above + CloudAppEvents, EmailEvents, AADUserRiskEvents | Steps 1-7 (full investigation) |
| M365 E3 + Entra ID P2 + Sentinel | OfficeActivity, SigninLogs, AuditLogs, AADUserRiskEvents | Steps 1-4, 6-7 + risk context |

---

## 3. Input Parameters

These parameters are shared across all queries. Replace with values from your alert.

```kql
// ============================================================
// SHARED INPUT PARAMETERS - Replace these for each investigation
// ============================================================
let TargetUser = "user@contoso.com";       // UPN from the alert
let AlertTime = datetime(2026-02-22T10:30:00Z);  // Time the rule creation was detected
let LookbackWindow = 24h;                 // Window before alert for sign-in context
let ForwardWindow = 72h;                  // Window after rule creation for exfiltration assessment
let BaselineDays = 30d;                   // Baseline comparison window
let ExternalDomain = "externaldomain.com"; // Forwarding destination domain (if known)
// ============================================================
```

---

## 4. Quick Triage Criteria

Use this decision matrix for immediate triage before running full investigation queries.

### Immediate Escalation (Skip to Containment)
- Rule forwards to external domain AND includes `DeleteMessage=true` or `MarkAsRead=true`
- Rule was created from an unfamiliar IP or location for the user
- User's account has active risk detections in Identity Protection
- Rule targets keywords like "invoice", "payment", "wire", "bank", "transfer"
- Multiple users have new forwarding rules to the same external domain
- `Set-Mailbox` with `ForwardingSmtpAddress` pointing to a personal email service (gmail.com, outlook.com, protonmail.com)

### Standard Investigation
- Rule forwards to external domain without evidence-hiding parameters
- Rule was created from a known IP but during unusual hours
- Single rule on a single user with no other indicators of compromise

### Likely Benign
- Rule forwards to another @contoso.com (internal) address
- Rule forwards to a known partner or vendor domain on an approved list
- User self-reports setting up forwarding for a known business reason
- Rule was created by an Exchange administrator for a shared mailbox
- Forwarding to known ticketing systems (e.g., support@contoso.zendesk.com)

---

## 5. Investigation Steps

### Step 1: Extract Inbox Rule Creation Event

**Purpose:** Identify the exact inbox rule creation or modification event, extract the full rule parameters, and determine who created the rule and from what session. This is the anchor event for the entire investigation.

**Data needed:** OfficeActivity

```kql
// ============================================================
// QUERY 1: Inbox Rule Creation/Modification Detection
// Purpose: Extract all inbox rule operations for the target user
// Tables: OfficeActivity
// Investigation Step: 1 - Extract Inbox Rule Creation Event
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:30:00Z);
let LookbackWindow = 24h;
// --- Find inbox rule creation, modification, and mailbox-level forwarding ---
OfficeActivity
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 2h))
| where UserId =~ TargetUser
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox", "Enable-InboxRule", "New-TransportRule")
| extend Parameters = parse_json(Parameters)
// --- Extract rule details from Parameters array ---
| extend
    RuleName = tostring(bag_pack_columns(Parameters)[0]),
    ForwardTo = extract(@'"ForwardTo"[^"]*"([^"]+)"', 1, tostring(Parameters)),
    ForwardAsAttachment = extract(@'"ForwardAsAttachmentTo"[^"]*"([^"]+)"', 1, tostring(Parameters)),
    RedirectTo = extract(@'"RedirectTo"[^"]*"([^"]+)"', 1, tostring(Parameters)),
    DeleteMessage = extract(@'"DeleteMessage"[^"]*"([^"]+)"', 1, tostring(Parameters)),
    MarkAsRead = extract(@'"MarkAsRead"[^"]*"([^"]+)"', 1, tostring(Parameters)),
    MoveToFolder = extract(@'"MoveToFolder"[^"]*"([^"]+)"', 1, tostring(Parameters)),
    SubjectContains = extract(@'"SubjectContainsWords"[^"]*"([^"]+)"', 1, tostring(Parameters)),
    BodyContains = extract(@'"BodyContainsWords"[^"]*"([^"]+)"', 1, tostring(Parameters)),
    FromAddress = extract(@'"From"[^"]*"([^"]+)"', 1, tostring(Parameters)),
    ForwardingSmtpAddress = extract(@'"ForwardingSmtpAddress"[^"]*"([^"]+)"', 1, tostring(Parameters)),
    DeliverToMailboxAndForward = extract(@'"DeliverToMailboxAndForward"[^"]*"([^"]+)"', 1, tostring(Parameters))
// --- Determine forwarding destination ---
| extend ForwardingDestination = coalesce(ForwardTo, ForwardAsAttachment, RedirectTo, ForwardingSmtpAddress)
// --- Flag external forwarding ---
| extend
    IsExternalForward = ForwardingDestination has "@" and not(ForwardingDestination has "@contoso.com"),
    HasEvidenceHiding = (DeleteMessage =~ "True" or MarkAsRead =~ "True" or isnotempty(MoveToFolder)),
    HasKeywordFilter = (isnotempty(SubjectContains) or isnotempty(BodyContains) or isnotempty(FromAddress))
| project
    TimeGenerated,
    UserId,
    Operation,
    ClientIP,
    SessionId,
    ForwardingDestination,
    IsExternalForward,
    HasEvidenceHiding,
    HasKeywordFilter,
    DeleteMessage,
    MarkAsRead,
    MoveToFolder,
    SubjectContains,
    BodyContains,
    RuleName,
    FullParameters = tostring(Parameters)
| sort by TimeGenerated desc
```

**Performance Notes:**
- OfficeActivity can be large; filtering on `UserId` and narrow time window first avoids full scans
- `parse_json(Parameters)` can fail on malformed entries — the `extract()` fallback pattern is more resilient

**Tuning Guidance:**
- Extend `LookbackWindow` to 72h if the alert was delayed by Defender for Cloud Apps processing
- If no results, check if the user created the rule via PowerShell (different Operation name) or OWA vs Outlook client

**Expected findings:**
- One or more rule creation events showing the exact forwarding destination
- `IsExternalForward = true` indicates mail leaving the organization
- `HasEvidenceHiding = true` is a strong indicator of malicious intent
- `HasKeywordFilter = true` suggests targeted exfiltration (BEC-style)

**Next action:**
- If external forwarding with evidence hiding → **Immediately escalate to containment while continuing investigation**
- If internal forwarding only → Proceed to Step 2 for deeper parameter analysis
- If `Set-Mailbox` with `ForwardingSmtpAddress` → This is server-side forwarding, higher severity than inbox rules

---

### Step 2: Rule Parameter Deep Dive

**Purpose:** Parse the full rule parameters to understand exactly what mail is being captured, where it's going, and what evidence-hiding techniques are in use. This step correlates multiple rules that may work together (e.g., one rule forwards, another hides).

**Data needed:** OfficeActivity

```kql
// ============================================================
// QUERY 2: Full Rule Parameter Analysis
// Purpose: Deep-dive into all inbox rules for the target user
// Tables: OfficeActivity
// Investigation Step: 2 - Rule Parameter Deep Dive
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:30:00Z);
// --- Get ALL inbox rule operations for this user in the past 30 days ---
// Attackers often create multiple complementary rules
OfficeActivity
| where TimeGenerated > ago(30d)
| where UserId =~ TargetUser
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox", "Remove-InboxRule", "Disable-InboxRule", "Enable-InboxRule")
// --- Parse each parameter into a readable format ---
| mv-expand Parameter = parse_json(Parameters)
| extend
    ParamName = tostring(Parameter.Name),
    ParamValue = tostring(Parameter.Value)
| summarize
    Params = make_bag(bag_pack(ParamName, ParamValue)),
    OperationTime = min(TimeGenerated)
    by TimeGenerated, Operation, ClientIP, SessionId
// --- Score rule risk ---
| extend
    HasForward = Params has "ForwardTo" or Params has "ForwardAsAttachmentTo" or Params has "RedirectTo" or Params has "ForwardingSmtpAddress",
    HasDelete = tostring(Params["DeleteMessage"]) =~ "True",
    HasMarkRead = tostring(Params["MarkAsRead"]) =~ "True",
    HasMoveFolder = isnotempty(tostring(Params["MoveToFolder"])),
    HasKeywords = isnotempty(tostring(Params["SubjectContainsWords"])) or isnotempty(tostring(Params["BodyContainsWords"])),
    HasSenderFilter = isnotempty(tostring(Params["From"]))
| extend RiskScore = toint(HasForward) * 3
    + toint(HasDelete) * 3
    + toint(HasMarkRead) * 2
    + toint(HasMoveFolder) * 1
    + toint(HasKeywords) * 2
    + toint(HasSenderFilter) * 1
| extend RiskLevel = case(
    RiskScore >= 6, "CRITICAL",
    RiskScore >= 4, "HIGH",
    RiskScore >= 2, "MEDIUM",
    "LOW"
)
| project TimeGenerated, Operation, ClientIP, RiskLevel, RiskScore, HasForward, HasDelete, HasMarkRead, HasKeywords, Params
| sort by RiskScore desc, TimeGenerated desc
```

**Expected findings:**
- CRITICAL rules: Forward + Delete (attacker stealing mail and covering tracks)
- HIGH rules: Forward to external domain with keyword filters (targeted BEC exfiltration)
- Multiple rules from the same session suggest automated/scripted compromise
- `Remove-InboxRule` shortly after `New-InboxRule` may indicate the attacker cleaned up after exfiltration

**Next action:**
- If CRITICAL risk rules found → Continue investigation AND begin containment in parallel
- If multiple rules found from different sessions → Attacker may have persistent access, check Step 3

---

### Step 3: Sign-In Context Analysis

**Purpose:** Determine whether the session that created the suspicious rule was itself suspicious. Correlate the OfficeActivity ClientIP and SessionId with SigninLogs to check for unfamiliar location, device, or risk signals.

**Data needed:** SigninLogs, AADUserRiskEvents (optional)

```kql
// ============================================================
// QUERY 3: Sign-In Context for Rule Creation Session
// Purpose: Analyze the authentication session that created the rule
// Tables: SigninLogs, OfficeActivity
// Investigation Step: 3 - Sign-In Context Analysis
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:30:00Z);
let LookbackWindow = 24h;
// --- First, get the ClientIP from the rule creation event ---
let RuleCreationIPs = OfficeActivity
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 2h))
| where UserId =~ TargetUser
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
| distinct ClientIP;
// --- Correlate with sign-in events from the same IP ---
SigninLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 2h))
| where UserPrincipalName =~ TargetUser
| extend
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion),
    State = tostring(LocationDetails.state),
    OS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    DeviceId = tostring(DeviceDetail.deviceId),
    IsCompliant = tostring(DeviceDetail.isCompliant),
    IsManaged = tostring(DeviceDetail.isManaged),
    MfaResult = tostring(MfaDetail.authMethod),
    CaStatus = ConditionalAccessStatus,
    RiskLevel = RiskLevelDuringSignIn,
    RiskState = RiskState
// --- Flag sign-ins from the rule creation IP ---
| extend IsRuleCreationSession = IPAddress in (RuleCreationIPs)
| project
    TimeGenerated,
    IPAddress,
    IsRuleCreationSession,
    ResultType,
    ResultDescription,
    AppDisplayName,
    ClientAppUsed,
    City,
    Country,
    OS,
    Browser,
    IsCompliant,
    IsManaged,
    MfaResult,
    CaStatus,
    RiskLevel,
    RiskState,
    AuthenticationRequirement
| sort by TimeGenerated desc
```

**Expected findings:**
- `IsRuleCreationSession = true` rows show the exact sign-in that preceded the rule creation
- Unfamiliar country/city + rule creation = high-confidence compromise
- `RiskLevel = high` during sign-in confirms Identity Protection flagged the session
- No MFA (`AuthenticationRequirement = singleFactorAuthentication`) combined with external forwarding is extremely suspicious
- `ClientAppUsed = "Exchange Web Services"` or `"PowerShell"` suggests automated/scripted rule creation

**Next action:**
- If sign-in was from a known location with MFA → Investigate whether the user's session was hijacked (token theft)
- If sign-in was from an unknown location without MFA → Likely credential compromise, proceed to Step 4
- If no matching sign-in found → Rule may have been created via delegated access or API; check AuditLogs for delegation

---

### Step 4: Baseline Comparison - Establish Normal Rule Creation Pattern

**Purpose:** Determine whether this user normally creates inbox rules and whether the current rule creation is anomalous. This is mandatory — you cannot determine malicious intent without understanding what "normal" looks like for this mailbox.

**Data needed:** OfficeActivity

```kql
// ============================================================
// QUERY 4: Inbox Rule Baseline Comparison (MANDATORY)
// Purpose: Establish normal inbox rule creation pattern for this user
// Tables: OfficeActivity
// Investigation Step: 4 - Baseline Comparison
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:30:00Z);
let BaselineDays = 30d;
// --- Historical rule activity for this user ---
let HistoricalRules = OfficeActivity
| where TimeGenerated between ((AlertTime - BaselineDays) .. AlertTime)
| where UserId =~ TargetUser
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox", "Remove-InboxRule", "Enable-InboxRule", "Disable-InboxRule")
| extend IsAlertWindow = TimeGenerated > (AlertTime - 24h)
| summarize
    TotalRuleOps = count(),
    BaselineRuleOps = countif(not(IsAlertWindow)),
    AlertWindowRuleOps = countif(IsAlertWindow),
    UniqueIPs = dcount(ClientIP),
    BaselineIPs = dcountif(ClientIP, not(IsAlertWindow)),
    AlertWindowIPs = dcountif(ClientIP, IsAlertWindow),
    Operations = make_set(Operation),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated);
// --- Compare alert-window activity to baseline ---
let Baseline = OfficeActivity
| where TimeGenerated between ((AlertTime - BaselineDays) .. (AlertTime - 24h))
| where UserId =~ TargetUser
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
| summarize
    BaselineOpsPerDay = round(1.0 * count() / max(datetime_diff('day', AlertTime - 24h, AlertTime - BaselineDays), 1), 2),
    BaselineDistinctOps = dcount(Operation),
    BaselineMaxOpsPerDay = max(OpsPerDay)
    by bin(TimeGenerated, 1d)
| extend OpsPerDay = 1
| summarize
    AvgDailyOps = round(avg(OpsPerDay), 2),
    MaxDailyOps = max(OpsPerDay),
    DaysWithActivity = count();
let TodayActivity = OfficeActivity
| where TimeGenerated between ((AlertTime - 24h) .. (AlertTime + 2h))
| where UserId =~ TargetUser
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
| summarize TodayOps = count(), TodayIPs = dcount(ClientIP);
Baseline
| join kind=rightouter TodayActivity on $left.AvgDailyOps == $right.TodayOps // cross join trick
| extend Assessment = case(
    isempty(AvgDailyOps) or AvgDailyOps == 0, "NO HISTORY - User has never created inbox rules before (SUSPICIOUS)",
    TodayOps > MaxDailyOps * 3, "ANOMALOUS - Significantly more rule operations than baseline",
    TodayOps > MaxDailyOps, "ELEVATED - Above normal rule creation activity",
    "WITHIN NORMAL RANGE"
)
| project Assessment, TodayOps, AvgDailyOps, MaxDailyOps, DaysWithActivity, TodayIPs
```

**Performance Notes:**
- 30-day OfficeActivity lookback on a single user is lightweight
- If the OfficeActivity table is very large, ensure the `UserId` filter is pushed down before the time filter

**Expected findings:**
- `NO HISTORY` is a strong suspicious signal — most users never manually create inbox rules
- `ANOMALOUS` combined with unfamiliar IP from Step 3 is high-confidence malicious
- Users who regularly manage their rules (IT admins, power users) will have baseline activity to compare against
- New IP addresses in alert window that were never seen in baseline period are a strong indicator

**Next action:**
- `NO HISTORY` or `ANOMALOUS` → Continue to Step 5 to assess exfiltration volume
- `WITHIN NORMAL RANGE` from a known IP → Likely benign; verify with user and close

---

### Step 5: Forwarded Email Volume Assessment

**Purpose:** Determine how many emails have already been forwarded or auto-forwarded to the external destination since the rule was created. This establishes the scope of potential data exposure and is critical for incident severity classification.

**Data needed:** EmailEvents (MDO P2) or OfficeActivity

```kql
// ============================================================
// QUERY 5A: Auto-Forwarded Email Tracking (Requires MDO P2)
// Purpose: Count and characterize emails forwarded to external destinations
// Tables: EmailEvents
// Investigation Step: 5 - Forwarded Email Volume Assessment
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:30:00Z);
let ForwardWindow = 72h;
let ExternalDomain = "externaldomain.com";
// --- Track auto-forwarded emails ---
EmailEvents
| where TimeGenerated between (AlertTime .. (AlertTime + ForwardWindow))
| where SenderMailFromAddress =~ TargetUser or SenderFromAddress =~ TargetUser
| where EmailDirection == "Outbound"
// --- Identify auto-forwarded emails by delivery action or subject pattern ---
| where DeliveryAction == "Delivered"
| where RecipientEmailAddress has ExternalDomain
    or RecipientEmailAddress has "gmail.com"
    or RecipientEmailAddress has "outlook.com"
    or RecipientEmailAddress has "protonmail.com"
    or RecipientEmailAddress has "yahoo.com"
| summarize
    ForwardedCount = count(),
    UniqueRecipients = dcount(RecipientEmailAddress),
    Recipients = make_set(RecipientEmailAddress, 10),
    SubjectSamples = make_set(Subject, 5),
    FirstForwarded = min(TimeGenerated),
    LastForwarded = max(TimeGenerated),
    TotalSize = sum(EmailClusterSize)
| extend
    ExfiltrationDuration = LastForwarded - FirstForwarded,
    Severity = case(
        ForwardedCount > 100, "CRITICAL - Mass email exfiltration",
        ForwardedCount > 20, "HIGH - Significant email forwarding",
        ForwardedCount > 5, "MEDIUM - Some emails forwarded",
        "LOW - Minimal forwarding detected"
    )
```

```kql
// ============================================================
// QUERY 5B: OfficeActivity-Based Forward Detection (No MDO P2 needed)
// Purpose: Detect forwarding activity via OfficeActivity send events
// Tables: OfficeActivity
// Investigation Step: 5 - Forwarded Email Volume Assessment (Fallback)
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:30:00Z);
let ForwardWindow = 72h;
// --- Track mail send events that may be auto-forwards ---
OfficeActivity
| where TimeGenerated between (AlertTime .. (AlertTime + ForwardWindow))
| where UserId =~ TargetUser
| where Operation in ("Send", "SendAs", "SendOnBehalf", "MailItemsAccessed")
| where OfficeWorkload == "Exchange"
// --- Focus on outbound items ---
| summarize
    TotalMailOps = count(),
    SendOps = countif(Operation == "Send"),
    MailAccessed = countif(Operation == "MailItemsAccessed"),
    UniqueIPs = dcount(ClientIP),
    IPs = make_set(ClientIP, 5)
    by bin(TimeGenerated, 1h)
| sort by TimeGenerated asc
// Look for spikes in outbound mail that correlate with rule creation time
```

**Expected findings:**
- Query 5A (if MDO P2 available): Exact count and recipients of forwarded mail
- Query 5B (fallback): Volume trends showing mail activity spikes post-rule-creation
- `CRITICAL` severity if 100+ emails forwarded — immediate escalation to legal/compliance
- Subject samples reveal what data was exposed (financial, HR, legal communications)

**Next action:**
- If significant forwarding detected → Quantify data exposure for legal/compliance reporting, proceed to containment
- If no forwarding detected → Rule may have been created but not yet triggered; still proceed to remove it

---

### Step 6: Cross-Reference with Persistence Mechanisms

**Purpose:** Check if the attacker established additional persistence beyond the forwarding rule — OAuth app consent, MFA method changes, delegate permissions, or other inbox manipulations. A forwarding rule alone is rarely the only post-compromise action.

**Data needed:** AuditLogs, OfficeActivity

```kql
// ============================================================
// QUERY 6: Post-Compromise Persistence Detection
// Purpose: Identify additional persistence mechanisms set by the attacker
// Tables: AuditLogs, OfficeActivity
// Investigation Step: 6 - Cross-Reference with Persistence Mechanisms
// ============================================================
let TargetUser = "user@contoso.com";
let AlertTime = datetime(2026-02-22T10:30:00Z);
let LookbackWindow = 24h;
// --- Part A: Entra ID directory changes (OAuth, MFA, roles) ---
let DirectoryChanges = AuditLogs
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
| where OperationName in (
    "Consent to application",
    "Add app role assignment to service principal",
    "Update user",
    "Add member to role",
    "Add eligible member to role",
    "Add owner to application",
    "Add delegated permission grant",
    "User registered security info",
    "User deleted security info",
    "Admin registered security info"
)
| where TargetResources has TargetUser or InitiatedBy has TargetUser
| project
    TimeGenerated,
    OperationName,
    Category,
    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    ModifiedProperties = tostring(TargetResources[0].modifiedProperties),
    AdditionalDetails = tostring(AdditionalDetails),
    CorrelationId
| extend ActionType = "DirectoryChange";
// --- Part B: Exchange delegate and permission changes ---
let ExchangeChanges = OfficeActivity
| where TimeGenerated between ((AlertTime - LookbackWindow) .. (AlertTime + 4h))
| where UserId =~ TargetUser or tostring(parse_json(Parameters)) has TargetUser
| where Operation in (
    "Add-MailboxPermission",
    "Add-RecipientPermission",
    "Set-Mailbox",
    "Add-MailboxFolderPermission",
    "UpdateCalendarDelegation",
    "Set-OwaMailboxPolicy"
)
| project
    TimeGenerated,
    OperationName = Operation,
    Category = "ExchangeAdmin",
    InitiatedBy = UserId,
    TargetUser = TargetUser,
    ModifiedProperties = tostring(Parameters),
    AdditionalDetails = "",
    CorrelationId = ""
| extend ActionType = "ExchangeChange";
// --- Combine all persistence indicators ---
DirectoryChanges
| union ExchangeChanges
| sort by TimeGenerated asc
| extend
    RiskIndicator = case(
        OperationName has "Consent to application", "HIGH - OAuth app consent (potential persistent API access)",
        OperationName has "registered security info", "HIGH - MFA method added (attacker registering own device)",
        OperationName has "deleted security info", "CRITICAL - MFA method removed (defense evasion)",
        OperationName has "Add member to role", "CRITICAL - Privilege escalation",
        OperationName has "Add-MailboxPermission", "HIGH - Mailbox delegation added",
        OperationName has "Add owner to application", "HIGH - App ownership (persistent access)",
        "MEDIUM - Suspicious directory change"
    )
```

**Expected findings:**
- OAuth application consent within hours of rule creation = attacker establishing API-level persistence
- MFA method registration = attacker registering their own authenticator device
- Mailbox delegation = attacker granting additional mailbox access beyond forwarding
- If NO additional persistence found → The attacker may be in early stages, or this is a false positive

**Next action:**
- If additional persistence mechanisms found → Expand containment scope to revoke OAuth tokens, remove MFA methods, check all delegated permissions
- If no additional persistence → Forwarding rule may be an isolated action; still remove and reset credentials

---

### Step 7: Org-Wide Forwarding Rule Sweep

**Purpose:** Determine whether this is an isolated incident or part of a broader campaign. Check if other users in the organization had suspicious forwarding rules created recently, particularly to the same external domain.

**Data needed:** OfficeActivity

```kql
// ============================================================
// QUERY 7: Org-Wide Suspicious Forwarding Rule Detection
// Purpose: Sweep the tenant for similar forwarding rules
// Tables: OfficeActivity
// Investigation Step: 7 - Org-Wide Forwarding Rule Sweep
// ============================================================
let AlertTime = datetime(2026-02-22T10:30:00Z);
let SweepWindow = 7d;
let ExternalDomain = "externaldomain.com";
// --- Find ALL forwarding rule creation events across the org ---
OfficeActivity
| where TimeGenerated between ((AlertTime - SweepWindow) .. (AlertTime + 1d))
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
| where OfficeWorkload == "Exchange"
// --- Extract forwarding destination from Parameters ---
| extend Params = tostring(Parameters)
| where Params has "ForwardTo"
    or Params has "ForwardAsAttachmentTo"
    or Params has "RedirectTo"
    or Params has "ForwardingSmtpAddress"
// --- Extract the destination address ---
| extend ForwardDest = extract(@'(?:ForwardTo|ForwardAsAttachmentTo|RedirectTo|ForwardingSmtpAddress)[^@]*@([a-zA-Z0-9.-]+)', 1, Params)
| extend FullForwardAddress = extract(@'(?:ForwardTo|ForwardAsAttachmentTo|RedirectTo|ForwardingSmtpAddress)[^"]*"([^"]+@[^"]+)"', 1, Params)
// --- Flag external domains ---
| where ForwardDest !has "contoso.com" and isnotempty(ForwardDest)
| summarize
    AffectedUsers = dcount(UserId),
    Users = make_set(UserId, 20),
    RuleCount = count(),
    Destinations = make_set(FullForwardAddress, 10),
    DestinationDomains = make_set(ForwardDest, 10),
    FirstCreated = min(TimeGenerated),
    LastCreated = max(TimeGenerated),
    SourceIPs = make_set(ClientIP, 10)
    by ForwardDest
| extend
    CampaignRisk = case(
        AffectedUsers >= 5, "CRITICAL - Multi-user campaign detected",
        AffectedUsers >= 2 and ForwardDest == ExternalDomain, "HIGH - Same external destination as alert",
        AffectedUsers >= 2, "MEDIUM - Multiple users forwarding to same domain",
        "LOW - Isolated incident"
    )
| sort by AffectedUsers desc
```

**Expected findings:**
- `CRITICAL` if multiple users forward to the same external domain — this is a coordinated campaign
- Same source IPs across multiple users suggests a single attacker with multiple compromised accounts
- Time clustering of rule creation events reveals the attacker's operational window
- If only the target user is affected → Isolated BEC, scope is limited to one mailbox

**Next action:**
- If campaign detected → Escalate to full incident response; all affected users need simultaneous containment
- If isolated → Continue with single-user containment per Section 6

---

## 6. Containment Playbook

### Immediate Actions (Within 15 Minutes)

1. **Remove the forwarding rule** — Connect to Exchange Online PowerShell and remove the malicious inbox rule:
   - `Get-InboxRule -Mailbox user@contoso.com | Where-Object {$_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo}`
   - `Remove-InboxRule -Mailbox user@contoso.com -Identity "RuleName" -Confirm:$false`
   - Also check server-side forwarding: `Get-Mailbox user@contoso.com | FL ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward`
   - Clear server-side forwarding: `Set-Mailbox user@contoso.com -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false`
2. **Reset the user's password** — Force an immediate password reset via Entra ID
3. **Revoke all active sessions** — Use `Revoke-AzureADUserAllRefreshToken` or Entra admin center
4. **If attacker registered MFA methods** — Remove any MFA methods added during the compromise window

### Conditional Actions

5. **If OAuth apps were consented** → Revoke consent and disable the application: `Remove-AzureADOAuth2PermissionGrant`
6. **If mailbox delegation was added** → Remove delegated permissions: `Remove-MailboxPermission`
7. **If server-side transport rules were modified** → Review and revert Exchange transport rules
8. **If multiple users affected** → Execute containment for all affected users simultaneously

### Follow-up (Within 4 Hours)

9. **Enable Conditional Access policy** blocking external email forwarding (if not already in place)
10. **Block the external domain** at the Exchange transport rule level to prevent re-creation
11. **Notify the user** that their account was compromised and forwarding was in place
12. **If financial data was forwarded** → Notify finance department and monitor for BEC fraud attempts

### Extended (Within 24 Hours)

13. **Implement Exchange Online mail flow rule** to block auto-forwarding to external domains org-wide
14. **Review all inbox rules** across high-value accounts (finance, executives, legal)
15. **Submit the external forwarding domain** to Microsoft as a malicious domain if confirmed threat
16. **User security training** on phishing and credential hygiene

---

## 7. Evidence Collection Checklist

- [ ] Full OfficeActivity log export for the affected user (30-day window)
- [ ] Screenshot of the malicious inbox rule details (name, conditions, actions)
- [ ] Sign-in logs showing the session that created the rule (IP, location, device, MFA status)
- [ ] List of emails forwarded to the external address (subjects, timestamps, recipients)
- [ ] Exchange Online inbox rule export: `Get-InboxRule -Mailbox user@contoso.com | Export-Csv`
- [ ] Server-side forwarding configuration: `Get-Mailbox user@contoso.com | FL Forward*`
- [ ] Any OAuth application consents granted during the compromise window
- [ ] MFA registration/deregistration events from the compromise window
- [ ] Identity Protection risk events for the affected user
- [ ] Message trace results for emails to/from the external domain
- [ ] If BEC suspected: copies of any financial emails forwarded (for fraud investigation)

---

## 8. Escalation Criteria

### Escalate to Incident Commander
- Multiple users have forwarding rules to the same external domain (campaign)
- The compromised user is in finance, legal, or executive leadership
- Evidence of active BEC fraud (wire transfer request modifications observed)
- Server-side `ForwardingSmtpAddress` was set (bypasses inbox rule controls)

### Escalate to Threat Intelligence
- The external forwarding domain appears in threat intelligence feeds
- The attack pattern matches known APT TTPs (e.g., Scattered Spider post-compromise playbook)
- Multiple persistence mechanisms (forwarding + OAuth + MFA) suggest a sophisticated actor
- The forwarding destination uses a look-alike domain (typosquatting)

### Escalate to Legal/Compliance
- Financial data (invoices, wire transfers, bank details) was forwarded to external addresses
- PII or health records (PHI) were exfiltrated
- The forwarding was active for more than 7 days before detection
- Regulated data (GDPR, HIPAA, SOX) may have been exposed
- The incident may require breach notification under applicable law

---

## 9. False Positive Documentation

### FP Scenario 1: User Self-Configuring Forwarding for Job Transition
**Pattern:** Employee forwards work email to personal account during notice period or while transitioning between roles. Rule created from the user's known IP, known device, during business hours.
**How to confirm:** Contact user or their manager. Check if employee is in notice period. Verify the forwarding address belongs to the user.
**Tuning note:** Consider creating an allow-list for forwarding to domains of known partner organizations. Still flag and review even if allowed — data loss risk exists.

### FP Scenario 2: IT Admin Configuring Shared Mailbox Forwarding
**Pattern:** Exchange administrator creates forwarding rules on shared/service mailboxes as part of routine operations. The `UserId` in OfficeActivity is the admin, not the mailbox owner.
**How to confirm:** Verify the admin performed the action via change management ticket. Check that the destination is an internal or approved external address.
**Tuning note:** Exclude service accounts and shared mailboxes from alerting, or create a separate lower-severity alert for admin-initiated forwarding.

### FP Scenario 3: Ticketing System Integration
**Pattern:** Auto-forwarding configured to route emails to helpdesk systems (ServiceNow, Jira Service Management, Zendesk). Rules are often created by IT during initial setup.
**How to confirm:** Verify the forwarding destination matches a known ticketing system domain. Check the rule was created by IT staff via approved process.
**Tuning note:** Whitelist known ticketing system domains. These rules should still be audited periodically but do not need real-time investigation.

### FP Scenario 4: Compliance Journaling Rules
**Pattern:** Organization-wide or per-mailbox journaling rules that forward copies to compliance/archival systems. These are standard in regulated industries.
**How to confirm:** Verify the destination is the organization's compliance archive or eDiscovery mailbox. Check with compliance team.
**Tuning note:** Exclude journaling destinations from the external forwarding alert. These are configured at the transport rule level and rarely appear in OfficeActivity `New-InboxRule` events.

---

## 10. MITRE ATT&CK Mapping

### Detection Coverage Matrix

| Technique ID | Technique Name | Tactic | Confidence | Query |
|---|---|---|---|---|
| T1114.003 | Email Collection: Email Forwarding Rule | Collection | **Confirmed** | Q1, Q2, Q7 |
| T1564.008 | Hide Artifacts: Email Hiding Rules | Defense Evasion | **Confirmed** | Q1, Q2 |
| T1114.002 | Email Collection: Remote Email Collection | Collection | **Probable** | Q5A, Q5B |
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | **Confirmed** | Q3 |
| T1534 | Internal Spearphishing | Lateral Movement | **Probable** | Q6 |
| T1098.002 | Account Manipulation: Additional Email Delegate Permissions | Persistence | **Probable** | Q6 |

### Attack Chains

**Chain 1: Phishing → BEC → Wire Fraud (Most Common)**
```
Credential phishing email (T1566.002)
  → User enters credentials on fake login page (T1078.004)
  → Attacker creates inbox forwarding rule (T1114.003)
  → Forwarded emails include "invoice" and "payment" keywords
  → Attacker monitors financial conversations for weeks
  → Attacker injects modified invoice with new banking details
  → Wire transfer fraud ($50K-$5M typical loss)
```

**Chain 2: Token Theft → Silent Surveillance → Data Exfiltration**
```
Adversary-in-the-middle phishing steals session token (T1557)
  → Attacker accesses mailbox via stolen token (T1078.004)
  → Creates forwarding rule with DeleteMessage=true (T1114.003 + T1564.008)
  → All incoming mail silently copied to external address
  → Original messages deleted — user sees empty inbox (partial)
  → Months of email exfiltrated before detection (T1114.002)
```

**Chain 3: Compromise → Multi-Persistence → Lateral Movement**
```
Password spray succeeds against target account (T1110.003)
  → Attacker registers own MFA device (T1556.006)
  → Creates inbox forwarding to external domain (T1114.003)
  → Grants OAuth app permissions for API access (T1528)
  → Adds delegate access to executive mailboxes (T1098.002)
  → Uses compromised mailbox for internal phishing (T1534)
  → Expands to additional accounts via trusted sender
```

### Threat Actor Attribution

| Actor | Confidence | Key TTPs |
|---|---|---|
| **Scattered Spider (Octo Tempest)** | **HIGH** | Creates forwarding rules post-MFA-fatigue compromise. Targets finance and IT staff mailboxes. |
| **Midnight Blizzard (APT29)** | **HIGH** | Inbox rule manipulation for long-term intelligence collection. Used in Microsoft corporate breach. |
| **Peach Sandstorm (APT33)** | **MEDIUM** | Post-spray compromise mailbox manipulation for intelligence gathering on defense/energy targets. |
| **Storm-0539 (Atlas Lion)** | **MEDIUM** | Creates forwarding rules targeting gift card and payment-related emails for financial fraud. |
| **Volt Typhoon** | **LOW** | Known to establish email-based persistence in critical infrastructure targets for long-term access. |

---

## 11. Query Summary

| Query | Purpose | Tables | Step |
|---|---|---|---|
| Q1 | Inbox rule creation/modification detection | OfficeActivity | 1 |
| Q2 | Full rule parameter analysis with risk scoring | OfficeActivity | 2 |
| Q3 | Sign-in context for rule creation session | SigninLogs, OfficeActivity | 3 |
| Q4 | 30-day rule creation baseline [MANDATORY] | OfficeActivity | 4 |
| Q5A | Auto-forwarded email tracking (MDO P2) | EmailEvents | 5 |
| Q5B | Forwarding activity via OfficeActivity (fallback) | OfficeActivity | 5 |
| Q6 | Post-compromise persistence detection | AuditLogs, OfficeActivity | 6 |
| Q7 | Org-wide forwarding rule sweep | OfficeActivity | 7 |

---

## Appendix A: Datatable Tests

### Test 1: Inbox Rule Detection with Risk Scoring

```kql
// ============================================================
// TEST 1: Inbox Rule Detection and Risk Scoring
// Validates: Query 1 + Query 2 - Rule extraction and risk classification
// Expected: Rule "AutoForward" = CRITICAL (forward + delete)
//           Rule "BackupMail" = MEDIUM (forward only, no hiding)
//           Rule "OrganizeInbox" = LOW (no forwarding)
// ============================================================
let TestOfficeActivity = datatable(
    TimeGenerated: datetime,
    UserId: string,
    Operation: string,
    ClientIP: string,
    SessionId: string,
    OfficeWorkload: string,
    Parameters: dynamic
) [
    // --- Malicious: Forward to external + delete originals ---
    datetime(2026-02-22T10:30:00Z), "user@contoso.com", "New-InboxRule", "203.0.113.50", "sess-001", "Exchange",
    dynamic([
        {"Name": "Name", "Value": "AutoForward"},
        {"Name": "ForwardTo", "Value": "attacker@externaldomain.com"},
        {"Name": "DeleteMessage", "Value": "True"},
        {"Name": "MarkAsRead", "Value": "True"},
        {"Name": "SubjectContainsWords", "Value": "invoice;payment;wire"}
    ]),
    // --- Suspicious: Forward to personal email, no hiding ---
    datetime(2026-02-22T11:00:00Z), "user@contoso.com", "New-InboxRule", "10.0.0.5", "sess-002", "Exchange",
    dynamic([
        {"Name": "Name", "Value": "BackupMail"},
        {"Name": "ForwardTo", "Value": "user.personal@gmail.com"}
    ]),
    // --- Benign: Organize inbox, no forwarding ---
    datetime(2026-02-22T11:30:00Z), "user@contoso.com", "New-InboxRule", "10.0.0.5", "sess-003", "Exchange",
    dynamic([
        {"Name": "Name", "Value": "OrganizeInbox"},
        {"Name": "MoveToFolder", "Value": "Newsletters"},
        {"Name": "SubjectContainsWords", "Value": "unsubscribe;newsletter"}
    ])
];
// --- Run rule analysis with risk scoring ---
TestOfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
| mv-expand Parameter = Parameters
| extend
    ParamName = tostring(Parameter.Name),
    ParamValue = tostring(Parameter.Value)
| summarize Params = make_bag(bag_pack(ParamName, ParamValue))
    by TimeGenerated, UserId, Operation, ClientIP, SessionId
| extend
    RuleName = tostring(Params["Name"]),
    HasForward = Params has "ForwardTo" or Params has "ForwardAsAttachmentTo" or Params has "RedirectTo",
    HasDelete = tostring(Params["DeleteMessage"]) =~ "True",
    HasMarkRead = tostring(Params["MarkAsRead"]) =~ "True",
    HasMoveFolder = isnotempty(tostring(Params["MoveToFolder"])) and not(Params has "ForwardTo"),
    HasKeywords = isnotempty(tostring(Params["SubjectContainsWords"]))
| extend RiskScore = toint(HasForward) * 3
    + toint(HasDelete) * 3
    + toint(HasMarkRead) * 2
    + toint(HasKeywords and HasForward) * 2
| extend RiskLevel = case(
    RiskScore >= 6, "CRITICAL",
    RiskScore >= 4, "HIGH",
    RiskScore >= 2, "MEDIUM",
    "LOW"
)
| project RuleName, RiskLevel, RiskScore, HasForward, HasDelete, HasMarkRead, HasKeywords, ClientIP
// Expected: "AutoForward" = CRITICAL (RiskScore=10: forward+delete+markread+keywords)
// Expected: "BackupMail" = MEDIUM (RiskScore=3: forward only)
// Expected: "OrganizeInbox" = LOW (RiskScore=0: no forwarding)
```

### Test 2: Sign-In Context Correlation

```kql
// ============================================================
// TEST 2: Sign-In Context Correlation
// Validates: Query 3 - Correlates rule creation IP with sign-in events
// Expected: 203.0.113.50 flagged as suspicious (foreign IP, no MFA)
//           10.0.0.5 flagged as known (corporate IP, MFA)
// ============================================================
let TestOfficeActivity = datatable(
    TimeGenerated: datetime,
    UserId: string,
    Operation: string,
    ClientIP: string
) [
    datetime(2026-02-22T10:30:00Z), "user@contoso.com", "New-InboxRule", "203.0.113.50",
    datetime(2026-02-22T11:00:00Z), "user@contoso.com", "New-InboxRule", "10.0.0.5"
];
let TestSigninLogs = datatable(
    TimeGenerated: datetime,
    UserPrincipalName: string,
    IPAddress: string,
    ResultType: string,
    LocationDetails: dynamic,
    DeviceDetail: dynamic,
    AuthenticationRequirement: string,
    ConditionalAccessStatus: string,
    RiskLevelDuringSignIn: string,
    AppDisplayName: string,
    ClientAppUsed: string
) [
    // --- Suspicious sign-in: foreign IP, no MFA, EWS ---
    datetime(2026-02-22T10:25:00Z), "user@contoso.com", "203.0.113.50", "0",
    dynamic({"city": "Lagos", "countryOrRegion": "NG"}),
    dynamic({"operatingSystem": "", "browser": ""}),
    "singleFactorAuthentication", "notApplied", "high", "Exchange Web Services", "Other clients",
    // --- Legitimate sign-in: corporate IP, MFA, Outlook ---
    datetime(2026-02-22T10:55:00Z), "user@contoso.com", "10.0.0.5", "0",
    dynamic({"city": "Istanbul", "countryOrRegion": "TR"}),
    dynamic({"operatingSystem": "Windows 11", "browser": "Outlook 16.0"}),
    "multiFactorAuthentication", "success", "none", "Microsoft Outlook", "Mobile Apps and Desktop clients"
];
// --- Correlate ---
let RuleCreationIPs = TestOfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
| distinct ClientIP;
TestSigninLogs
| where UserPrincipalName =~ "user@contoso.com"
| extend
    IsRuleCreationSession = IPAddress in (RuleCreationIPs),
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion)
| extend SessionRisk = case(
    AuthenticationRequirement == "singleFactorAuthentication" and RiskLevelDuringSignIn == "high", "CRITICAL - No MFA + High Risk",
    AuthenticationRequirement == "singleFactorAuthentication", "HIGH - No MFA",
    RiskLevelDuringSignIn in ("high", "medium"), "MEDIUM - Risk detected but MFA passed",
    "LOW - Normal session"
)
| project TimeGenerated, IPAddress, IsRuleCreationSession, City, Country, AuthenticationRequirement, RiskLevelDuringSignIn, SessionRisk, AppDisplayName
// Expected: 203.0.113.50 = "CRITICAL - No MFA + High Risk" (Lagos, singleFactor, high risk)
// Expected: 10.0.0.5 = "LOW - Normal session" (Istanbul, multiFactor, no risk)
```

### Test 3: Baseline Comparison

```kql
// ============================================================
// TEST 3: Rule Creation Baseline Comparison
// Validates: Query 4 - Compares current rule activity to 30-day baseline
// Expected: user@contoso.com = "NO HISTORY" (never created rules before)
//           admin@contoso.com = "WITHIN NORMAL RANGE" (regularly manages rules)
// ============================================================
let TestOfficeActivity = datatable(
    TimeGenerated: datetime,
    UserId: string,
    Operation: string,
    ClientIP: string
) [
    // --- admin@contoso.com: Regular rule management over 30 days ---
    datetime(2026-01-25T09:00:00Z), "admin@contoso.com", "New-InboxRule", "10.0.0.1",
    datetime(2026-01-28T14:00:00Z), "admin@contoso.com", "Set-InboxRule", "10.0.0.1",
    datetime(2026-02-03T10:00:00Z), "admin@contoso.com", "New-InboxRule", "10.0.0.1",
    datetime(2026-02-10T11:00:00Z), "admin@contoso.com", "Set-InboxRule", "10.0.0.1",
    datetime(2026-02-17T09:30:00Z), "admin@contoso.com", "New-InboxRule", "10.0.0.1",
    // Today: admin creates one more rule (normal)
    datetime(2026-02-22T10:00:00Z), "admin@contoso.com", "New-InboxRule", "10.0.0.1",
    // --- user@contoso.com: NEVER created rules before ---
    // Today: first ever rule creation (suspicious)
    datetime(2026-02-22T10:30:00Z), "user@contoso.com", "New-InboxRule", "203.0.113.50"
];
let AlertTime = datetime(2026-02-22T12:00:00Z);
let Users = dynamic(["user@contoso.com", "admin@contoso.com"]);
// --- Compute baseline per user ---
let Baseline = TestOfficeActivity
| where TimeGenerated < (AlertTime - 24h)
| where UserId in (Users)
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
| summarize BaselineOps = count(), BaselineDays = dcount(bin(TimeGenerated, 1d)) by UserId;
let Today = TestOfficeActivity
| where TimeGenerated >= (AlertTime - 24h)
| where UserId in (Users)
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
| summarize TodayOps = count() by UserId;
Today
| join kind=leftouter Baseline on UserId
| extend Assessment = case(
    isempty(BaselineOps) or BaselineOps == 0, "NO HISTORY - User has never created inbox rules (SUSPICIOUS)",
    TodayOps > BaselineOps, "ELEVATED - More rule operations than entire baseline period",
    "WITHIN NORMAL RANGE"
)
| project UserId, TodayOps, BaselineOps, BaselineDays, Assessment
// Expected: user@contoso.com = "NO HISTORY" (0 baseline operations)
// Expected: admin@contoso.com = "WITHIN NORMAL RANGE" (5 baseline ops over 4 days)
```

### Test 4: Org-Wide Forwarding Sweep

```kql
// ============================================================
// TEST 4: Org-Wide Forwarding Rule Campaign Detection
// Validates: Query 7 - Detects multi-user forwarding campaigns
// Expected: externaldomain.com = CRITICAL (3 users, same destination)
//           gmail.com = LOW (1 user, isolated)
// ============================================================
let TestOfficeActivity = datatable(
    TimeGenerated: datetime,
    UserId: string,
    Operation: string,
    ClientIP: string,
    OfficeWorkload: string,
    Parameters: dynamic
) [
    // --- Campaign: 3 users forwarding to same external domain ---
    datetime(2026-02-22T08:00:00Z), "finance1@contoso.com", "New-InboxRule", "203.0.113.50", "Exchange",
    dynamic([{"Name": "ForwardTo", "Value": "drop1@externaldomain.com"}, {"Name": "DeleteMessage", "Value": "True"}]),
    datetime(2026-02-22T08:15:00Z), "finance2@contoso.com", "New-InboxRule", "203.0.113.51", "Exchange",
    dynamic([{"Name": "ForwardTo", "Value": "drop2@externaldomain.com"}, {"Name": "DeleteMessage", "Value": "True"}]),
    datetime(2026-02-22T08:30:00Z), "cfo@contoso.com", "New-InboxRule", "203.0.113.52", "Exchange",
    dynamic([{"Name": "ForwardTo", "Value": "drop3@externaldomain.com"}, {"Name": "MarkAsRead", "Value": "True"}]),
    // --- Isolated: 1 user forwarding to personal gmail ---
    datetime(2026-02-22T09:00:00Z), "marketing@contoso.com", "New-InboxRule", "10.0.0.5", "Exchange",
    dynamic([{"Name": "ForwardTo", "Value": "personal.backup@gmail.com"}])
];
// --- Sweep for external forwarding ---
TestOfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
| mv-expand Param = Parameters
| where tostring(Param.Name) in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo", "ForwardingSmtpAddress")
| extend FullAddress = tostring(Param.Value)
| extend ForwardDomain = extract(@'@([a-zA-Z0-9.-]+)', 1, FullAddress)
| where ForwardDomain !has "contoso.com" and isnotempty(ForwardDomain)
| summarize
    AffectedUsers = dcount(UserId),
    Users = make_set(UserId, 20),
    RuleCount = count(),
    Destinations = make_set(FullAddress, 10),
    SourceIPs = make_set(ClientIP, 10)
    by ForwardDomain
| extend CampaignRisk = case(
    AffectedUsers >= 3, "CRITICAL - Multi-user campaign",
    AffectedUsers >= 2, "HIGH - Multiple users same domain",
    "LOW - Isolated incident"
)
| sort by AffectedUsers desc
// Expected: externaldomain.com = CRITICAL (3 affected users: finance1, finance2, cfo)
// Expected: gmail.com = LOW (1 user: marketing, isolated)
```

---

## References

- [Microsoft: Responding to a compromised email account in Office 365](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/responding-to-a-compromised-email-account)
- [Microsoft: Detect and remediate Outlook rules and custom forms injections attacks](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-outlook-rules-forms-attack)
- [Microsoft: Control automatic external email forwarding in Microsoft 365](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/outbound-spam-policies-external-email-forwarding)
- [Microsoft: Manage mail flow rules in Exchange Online](https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules)
- [MITRE ATT&CK T1114.003 - Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/)
- [MITRE ATT&CK T1564.008 - Hide Artifacts: Email Hiding Rules](https://attack.mitre.org/techniques/T1564/008/)
- [FBI IC3: Business Email Compromise - The $50 Billion Scam](https://www.ic3.gov/Media/Y2023/PSA230609)
- [CISA: Business Email Compromise](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a)
- [Microsoft: Scattered Spider threat actor profile](https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/)
