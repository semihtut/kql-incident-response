# Investigation Flow - MFA Fatigue Attack (RB-0005)

> **Author:** Arina (IR Architect)
> **Reviewed by:** Leo (Coordinator)
> **Version:** 1.0
> **Date:** 2026-02-22

## Alert Classification

| Field | Value |
|---|---|
| **Risk Detection Name** | `mfaFraud` (AADUserRiskEvents) + MFA denial pattern analysis (SigninLogs) |
| **Source** | Microsoft Entra ID Identity Protection |
| **Detection Type** | Combination: Real-time (Identity Protection mfaFraud) + Analytics (MFA denial pattern detection in SigninLogs) |
| **Severity** | High |
| **Description** | Fires when a user reports MFA fraud (pressing the fraud button in the Authenticator app) or when analysis detects a pattern of repeated MFA push denials followed by an eventual approval. MFA fatigue (also called MFA bombing or MFA push spam) occurs when an attacker who already possesses valid credentials repeatedly triggers MFA push notifications, hoping the user accidentally approves or approves out of frustration. The attacker ALREADY has the password -- this is not a credential attack, it is an MFA bypass attack. |

## Decision Tree

```
MFA FATIGUE / MFA FRAUD ALERT RECEIVED
│
├─ Step 1: Extract MFA fraud risk event and correlate to sign-in attempts
│   ├─ RiskEventType == "mfaFraud" in AADUserRiskEvents? → Continue with HIGH priority
│   ├─ No mfaFraud event? → Check SigninLogs for MFA denial pattern (ResultType == "500121")
│   ├─ Correlate by UserPrincipalName + TimeGenerated window → Get all sign-in attempts
│   ├─ Identify the source IP(s) triggering the MFA pushes → These are the ATTACKER's IPs
│   ├─ User pressed MFA fraud button? → CONFIRMED user is aware of attack → Step 2
│   └─ No fraud report but pattern detected? → User may not be aware → Step 2 + contact user
│
├─ Step 2: MFA denial pattern analysis (UNIQUE TO THIS RUNBOOK)
│   ├─ Count MFA denials (ResultType == "500121") for this user in a sliding 1-hour window
│   │   ├─ 1-2 denials? → LOW concern (normal user error, phone issues)
│   │   ├─ 3-5 denials in 1 hour? → MEDIUM concern → Step 3
│   │   ├─ 6-10 denials in 1 hour? → HIGH concern → Step 3 + prepare containment
│   │   └─ 10+ denials in 1 hour? → CRITICAL (active MFA bombing) → Step 3 + immediate containment
│   ├─ Check timing pattern between denials
│   │   ├─ Rapid-fire (< 30 seconds apart)? → Automated tool / scripted attack
│   │   ├─ Regular intervals (1-3 minutes apart)? → Manual but persistent attacker
│   │   └─ Irregular, spread over hours? → More cautious attacker or intermittent automation
│   ├─ Time-of-day analysis (CRITICAL for this runbook)
│   │   ├─ MFA pushes at 2-5 AM user's local time? → VERY HIGH suspicion (victim likely sleeping/groggy)
│   │   ├─ MFA pushes outside business hours (evenings, weekends)? → HIGH suspicion
│   │   └─ MFA pushes during business hours? → MEDIUM suspicion (attacker may be in same timezone)
│   ├─ Source IP analysis
│   │   ├─ All denials from single IP? → Single attacker endpoint
│   │   ├─ Denials from multiple IPs? → Distributed attack or rotating infrastructure
│   │   └─ IP(s) match user's known IPs? → LOW concern (user's own failed attempts)
│   └─ Check if MFA push was sent to registered device vs. unknown
│       ├─ Push to user's known device? → Expected (attacker triggers push to legitimate device)
│       └─ Push to unknown device? → MFA method may already be compromised → Step 5 immediately
│
├─ Step 3: Did the user eventually APPROVE after the denials? (THE CRITICAL PIVOT POINT)
│   ├─ Search SigninLogs: ResultType == 0 (success) for same user within 24h AFTER the denial cluster
│   │   ├─ Successful sign-in found from SAME IP as the denials?
│   │   │   ├─ YES → LIKELY COMPROMISE → Step 5 (session analysis) + prepare containment
│   │   │   └─ NO → Check if success came from a DIFFERENT IP
│   │   ├─ Successful sign-in found from DIFFERENT IP than denials?
│   │   │   ├─ Different IP but same user → Could be legitimate user sign-in → Step 4 to disambiguate
│   │   │   └─ Different IP + different device/browser than user baseline → SUSPICIOUS → Step 5
│   │   └─ NO successful sign-in found after the denials?
│   │       ├─ Defense held → Credential compromise CONFIRMED (attacker had password)
│   │       ├─ Password reset required (attacker has the password even though MFA blocked access)
│   │       └─ → Step 4 (baseline) then close with password reset + monitoring
│   ├─ Time gap between last denial and approval
│   │   ├─ Approval within minutes of denials? → User likely approved out of frustration → COMPROMISE
│   │   ├─ Approval hours later from same attacker IP? → Attacker persistence → COMPROMISE
│   │   └─ Approval next business day from user's known IP? → Likely user's legitimate sign-in → Step 4
│   └─ MFA method used for the successful approval
│       ├─ Push notification approved? → Classic MFA fatigue success
│       ├─ Phone call answered? → User may have answered out of frustration
│       ├─ FIDO2/passkey used? → Very unlikely to be MFA fatigue (requires physical key)
│       └─ SMS code entered? → Possible SIM swap or social engineering of SMS code
│
├─ Step 4: Baseline Comparison - Establish Normal MFA Behavior Pattern (30 days) [MANDATORY]
│   ├─ Calculate baseline MFA metrics for this specific user over 30 days
│   │   ├─ Average MFA challenges per day (normal frequency)
│   │   ├─ MFA denial rate (how often does this user normally deny/fail MFA?)
│   │   ├─ Typical MFA methods used (push, phone call, FIDO2, SMS)
│   │   ├─ Typical sign-in times (business hours vs. off-hours pattern)
│   │   └─ Typical source IPs and locations for MFA-challenged sign-ins
│   ├─ Compare current event against baseline
│   │   ├─ MFA denial count today vs. 30-day average → How many standard deviations?
│   │   ├─ Source IP seen in 30-day history? → If new IP + MFA denials → HIGH concern
│   │   ├─ Sign-in time within user's normal pattern? → Off-hours + MFA denials → HIGH concern
│   │   ├─ User has history of MFA denials (poor cell coverage, phone issues)? → Weight toward FP
│   │   └─ New account with <7 days of history? → Flag as additional risk (no baseline)
│   ├─ Determine if this user is a repeat MFA fatigue target
│   │   ├─ Prior mfaFraud events in past 90 days? → Persistent targeting → ESCALATE
│   │   └─ First occurrence? → Standard investigation → Step 5 or Step 6 based on Step 3 outcome
│   └─ Check organization-wide MFA denial patterns
│       ├─ Multiple users experiencing MFA denial spikes simultaneously? → Coordinated attack → ESCALATE
│       └─ Only this user affected? → Targeted attack on this specific user
│
├─ Step 5: Session analysis and post-access activity (ONLY IF MFA WAS APPROVED - from Step 3)
│   ├─ Extract the authenticated session details
│   │   ├─ SessionId and CorrelationId from the successful sign-in
│   │   ├─ Source IP, device, browser, application accessed
│   │   └─ Conditional Access policies applied/bypassed
│   ├─ Check AADNonInteractiveUserSignInLogs for the attacker session
│   │   ├─ Non-interactive sign-ins from attacker IP after approval? → Active token usage → CONFIRMED
│   │   ├─ Token refresh activity from attacker IP? → Persistent access established
│   │   ├─ Multiple resource access from attacker IP? → Lateral movement in progress
│   │   └─ Non-interactive activity continuing after business hours? → Attacker operating outside user's schedule
│   ├─ Check OfficeActivity for email/file access from attacker session
│   │   ├─ MailItemsAccessed with high volume (>100 in 1 hour)? → Bulk email harvesting → Containment
│   │   ├─ FileDownloaded from SharePoint/OneDrive in bulk? → Data exfiltration → Containment
│   │   ├─ Emails sent from compromised account? → BEC / internal phishing → Containment
│   │   └─ No post-access activity detected? → Attacker may be staging for later → Still contain
│   └─ Determine blast radius
│       ├─ How long between MFA approval and session revocation/detection?
│       ├─ What resources were accessed during that window?
│       └─ Were any other users contacted from the compromised account?
│
├─ Step 6: Directory changes and persistence mechanisms
│   ├─ Check AuditLogs for MFA method modifications (T1556.006)
│   │   ├─ New MFA method registered from attacker IP? → CONFIRMED persistence → Containment
│   │   ├─ MFA method changed within 24h of the fatigue attack? → HIGHLY suspicious
│   │   ├─ Authenticator app re-registered? → Attacker replacing user's MFA → CRITICAL → Containment
│   │   └─ No MFA changes? → Continue
│   ├─ Check AuditLogs for OAuth application consent (T1528)
│   │   ├─ New OAuth app consented with Mail.Read, Mail.ReadWrite, Files.ReadWrite.All? → CONFIRMED persistence
│   │   ├─ Consent granted from attacker IP? → CONFIRMED → Containment
│   │   └─ No new OAuth consents? → Continue
│   ├─ Check for inbox rule creation (T1564.008, T1114.003)
│   │   ├─ New-InboxRule with forwarding/deletion? → CONFIRMED BEC → Containment
│   │   ├─ Set-Mailbox with ForwardingSmtpAddress? → CONFIRMED exfiltration → Containment
│   │   └─ No inbox rule changes? → Continue
│   ├─ Check for role/group membership changes (T1098)
│   │   ├─ User added to privileged role? → CONFIRMED privilege escalation → CRITICAL → Containment
│   │   ├─ User added to sensitive groups? → CONFIRMED lateral movement → Containment
│   │   └─ No role/group changes? → Continue
│   └─ Check for device registration
│       ├─ New device registered from attacker IP? → Persistence mechanism → Containment
│       └─ No new devices? → Step 7
│
└─ Step 7: Email and file activity blast radius
    ├─ Check OfficeActivity for internal spearphishing (T1534)
    │   ├─ Emails sent to internal users with links/attachments? → Attacker spreading laterally
    │   ├─ Teams messages sent with suspicious content? → Cross-platform spread
    │   └─ No internal communication from attacker session? → Continue
    ├─ Check for data access and exfiltration (T1530)
    │   ├─ SharePoint/OneDrive files accessed in bulk? → Data staging → Containment
    │   ├─ Shared links created with external access? → Data exfiltration → Containment
    │   ├─ Files downloaded then deleted? → Anti-forensics → CRITICAL → Containment
    │   └─ Normal file access patterns? → Lower concern
    ├─ Determine total blast radius
    │   ├─ Duration of attacker access (first successful sign-in to detection/revocation)
    │   ├─ Number of resources accessed
    │   ├─ Number of users contacted from compromised account
    │   └─ Volume of data accessed or exfiltrated
    └─ Final classification based on all evidence → Classification Matrix
```

## Classification Matrix

| Classification | Key Criteria | Action |
|---|---|---|
| **True Positive - Confirmed Compromise** | MFA approved after denial cluster + post-access persistence found (inbox rules, MFA method changes, OAuth consent) OR bulk data access from attacker IP OR attacker registered new MFA method OR role/group changes made from attacker session | Immediate containment: revoke all sessions, reset password, remove attacker's MFA methods, remove persistence mechanisms, block attacker IP, contact user via out-of-band channel |
| **True Positive - Exposed (Defense Held)** | MFA denial cluster confirmed from attacker IP (3+ denials in 1 hour) but user did NOT approve. MFA defense held. However, the attacker possesses valid credentials (username + password). No unauthorized access occurred but credential compromise is confirmed. | Force immediate password reset, review MFA method strength (upgrade to FIDO2/number matching if using simple push), enable MFA fraud reporting, monitor for re-attack within 7 days, investigate how credentials were initially compromised |
| **Benign True Positive (BTP)** | Alert correctly fired (MFA denials occurred) but verified as legitimate: user had phone/connectivity issues causing MFA failures, user accidentally denied then re-attempted, MFA enrollment failures during initial setup, user in area with poor cell coverage causing push notification failures | Close as BTP, document reason, confirm with user via out-of-band channel that the MFA failures were their own actions |

## Key Differences from RB-0001, RB-0002, RB-0003, and RB-0004

1. **The attacker ALREADY has the password.** This is the fundamental difference from all prior runbooks. In RB-0001 (Unfamiliar Sign-In), RB-0002 (Impossible Travel), RB-0003 (Leaked Credentials), and RB-0004 (Anonymous IP), the investigation must determine whether credentials were compromised. In RB-0005, credential compromise is a given -- the attacker is actively authenticating with valid credentials. The investigation starts at the MFA layer, not the credential layer.

2. **MFA denial pattern analysis (Step 2) is entirely new.** No prior runbook analyzes MFA denial counts, timing, or frequency. This step uses ResultType == "500121" (MFA denied by user) as the primary signal and introduces sliding-window denial counting, inter-denial timing analysis, and time-of-day correlation. This is the signature investigation step for MFA fatigue.

3. **The denial-then-approval pivot (Step 3) defines two fundamentally different outcomes.** If the user approved after denials: the attacker gained access, and the investigation proceeds to blast radius assessment (Steps 5-7). If the user did NOT approve: the defense held, but credential compromise is still confirmed. No prior runbook has this binary pivot point that splits the investigation into two completely different paths.

4. **Time-of-day analysis is a primary signal.** Unlike RB-0001 through RB-0004 where time-of-day is a secondary indicator, in RB-0005 it is a primary investigation signal. MFA bombing at 2 AM when the victim is sleeping or groggy is a well-documented Scattered Spider tactic. The same pattern during business hours is far less conclusive.

5. **MITRE T1621 (Multi-Factor Authentication Request Generation) is new.** This is the first runbook to cover T1621, a technique specifically describing the generation of repeated MFA requests to bypass authentication. No prior runbook maps to this technique.

6. **Baseline comparison focuses on MFA behavior, not sign-in properties.** RB-0001 baselines location + device + browser. RB-0002 baselines travel patterns. RB-0003 baselines post-leak sign-in anomalies. RB-0004 baselines anonymous IP usage history. RB-0005 uniquely baselines MFA challenge frequency, MFA denial rate, and MFA method usage patterns -- metrics that are irrelevant in every other runbook.

7. **The false positive rate is lower (~20-30%) than prior Identity Protection runbooks.** RB-0004 has ~70-80% FP, RB-0002 has ~60-70% FP, RB-0001 has ~50-60% FP. Repeated MFA denials are inherently more suspicious than an unfamiliar IP or impossible travel, which have many benign explanations. The primary FP sources for RB-0005 are narrower: phone issues, accidental denials, MFA enrollment problems, and poor cell coverage.

8. **Known threat actor association is specific and well-documented.** Scattered Spider (Octo Tempest) has used MFA fatigue as a primary tactic in high-profile breaches (MGM Resorts, Caesars Entertainment, Okta customers). LAPSUS$ used the same technique against Uber and Microsoft. This is not a theoretical attack -- it is a documented TTPs of named, active threat groups. Prior runbooks map to broader threat actor groups; RB-0005 maps to specific, well-known campaigns.

9. **Even when the defense holds (user denies all pushes), the investigation is NOT complete.** In other runbooks, if the attacker fails to authenticate, the investigation can close relatively quickly. In RB-0005, even when every MFA push is denied, the attacker demonstrably possesses the user's password. A password reset is mandatory even in the "defense held" scenario. The investigation must also determine how the password was originally compromised.

## Estimated Investigation Time

| Scenario | Time |
|---|---|
| BTP quick close (user confirms own MFA failures due to phone issues, no denial pattern, baseline shows history of MFA problems) | 5-10 minutes |
| Defense held (MFA denials confirmed, user did NOT approve, no unauthorized access but password reset required) | 15-25 minutes |
| Standard investigation (all 7 steps, MFA approved but no post-access persistence found) | 30-45 minutes |
| Confirmed compromise with containment (MFA approved + persistence mechanisms + blast radius assessment) | 60-90 minutes |
| Coordinated attack (multiple users targeted simultaneously, Scattered Spider-style campaign, full org-wide hunting) | 120-180 minutes |
