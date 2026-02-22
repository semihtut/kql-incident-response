# Investigation Flow - Anonymous IP Address Sign-In (RB-0004)

> **Author:** Arina (IR Architect)
> **Reviewed by:** Leo (Coordinator)
> **Version:** 1.0
> **Date:** 2026-02-22

## Alert Classification

| Field | Value |
|---|---|
| **Risk Detection Name** | `anonymizedIPAddress` |
| **Source** | Microsoft Entra ID Identity Protection |
| **Detection Type** | Real-time |
| **Severity** | Medium |
| **Description** | Fires when a user signs in from an IP address identified as an anonymous proxy -- Tor exit nodes, anonymizing VPN services, known anonymization proxies, or other privacy-masking infrastructure |

## Decision Tree

```
ANONYMOUS IP ADDRESS SIGN-IN ALERT RECEIVED
│
├─ Step 1: Extract risk event and anonymous IP sign-in
│   ├─ RiskEventType == "anonymizedIPAddress" in AADUserRiskEvents? → Continue
│   ├─ Correlate to SigninLogs by CorrelationId → Get full sign-in context
│   ├─ Sign-in successful (ResultType == 0)? → HIGH priority → Step 2
│   ├─ Sign-in failed but MFA challenged? → MEDIUM priority → Step 2
│   └─ Sign-in failed at password stage? → LOWER priority → Still Step 2 (credential testing)
│
├─ Step 2: Anonymous IP classification
│   ├─ IP belongs to known Tor exit node? → HIGH concern (deliberate anonymization)
│   ├─ IP belongs to commercial VPN provider (NordVPN, ExpressVPN, etc.)? → MEDIUM concern (very common FP)
│   ├─ IP belongs to cloud proxy service (iCloud Private Relay, Google One VPN)? → LOW concern (consumer privacy feature)
│   ├─ IP belongs to hosting/VPS provider (AWS, Azure, DigitalOcean)? → HIGH concern (attack infrastructure)
│   ├─ IP belongs to open/public proxy? → HIGH concern (shared anonymization infra)
│   └─ Cannot classify? → MEDIUM concern → Continue investigation
│
├─ Step 3: Baseline Comparison - Establish Normal Sign-In Pattern (30 days) [MANDATORY]
│   ├─ User has history of signing in from VPN/anonymous IPs? → Weight toward FP
│   ├─ User's baseline shows consistent anonymous IP usage (e.g., privacy-conscious user)? → Likely BTP
│   ├─ User has NEVER signed in from anonymous IP before? → HIGH concern → Step 4
│   ├─ Same anonymous IP seen in user's baseline? → LOWER concern (habitual VPN)
│   ├─ New account with <7 days of history? → Flag as additional risk (no baseline)
│   └─ Compare sign-in time, location pattern, device, browser against 30-day norm
│
├─ Step 4: Sign-in session analysis
│   ├─ MFA completed successfully? → Lower concern (attacker less likely to pass MFA)
│   ├─ MFA not required (policy gap)? → HIGH concern → Check Conditional Access config
│   ├─ Legacy authentication protocol used? → CRITICAL (bypasses MFA) → Step 5 immediately
│   ├─ Device is managed/compliant? → Lower concern (corporate device on VPN)
│   ├─ Device is unmanaged + anonymous IP? → HIGH concern → Step 5
│   ├─ Browser user agent matches known automation (Python, curl, headless)? → CRITICAL → Step 5
│   └─ Application accessed is sensitive (Exchange Online, SharePoint, Azure Portal)? → Increase priority
│
├─ Step 5: Post-sign-in activity - Blast radius assessment
│   ├─ Inbox rules / forwarding created? → CONFIRMED BEC → Containment
│   ├─ MFA method registered from anonymous IP? → CONFIRMED persistence → Containment
│   ├─ OAuth app consented with broad permissions? → CONFIRMED persistence → Containment
│   ├─ Bulk email access (MailItemsAccessed > 100 in 1 hour)? → Data exposure → Containment
│   ├─ Mass file download from SharePoint/OneDrive? → Data exfiltration → Containment
│   ├─ Sent emails to internal/external recipients? → Phishing from compromised account → Containment
│   ├─ Password or account changes made? → Account takeover → Containment
│   └─ No suspicious post-sign-in activity? → Step 6
│
├─ Step 6: Non-interactive sign-in check from anonymous IP
│   ├─ AADNonInteractiveUserSignInLogs shows sign-ins from same anonymous IP? → Token in use → HIGH concern
│   ├─ Non-interactive sign-ins from anonymous IP accessing multiple resources? → Session hijacking → Containment
│   ├─ Refresh token activity from anonymous IP after interactive sign-in? → Persistent access confirmed
│   ├─ Non-interactive sign-ins continuing AFTER user's normal session ended? → CRITICAL → Containment
│   └─ No non-interactive sign-ins from anonymous IP? → Step 7
│
└─ Step 7: IP reputation and organizational context
    ├─ IP found in ThreatIntelligenceIndicator feeds? → HIGH confidence malicious → Containment
    ├─ Same anonymous IP used by OTHER users in the org? → Likely shared corporate VPN → Lower concern
    ├─ IP flagged for multiple risk events across different users? → Attack infrastructure → Containment
    ├─ IP associated with known threat actor infrastructure? → CRITICAL → Containment + Escalate
    ├─ IP is in same ASN as other anonymous IPs seen in org? → Pattern analysis needed
    └─ Clean reputation + no other indicators + commercial VPN → Close as BTP
```

## Classification Matrix

| Classification | Key Criteria | Action |
|---|---|---|
| **True Positive - Confirmed Compromise** | Post-sign-in persistence found (inbox rules, MFA registration, OAuth consent) OR bulk data access from anonymous IP OR TI-matched IP + non-interactive token usage OR legacy auth bypass from Tor/proxy | Immediate containment: revoke sessions, reset password, block IP, remove persistence mechanisms |
| **True Positive - Exposed** | Successful sign-in from anonymous IP with no detected post-sign-in abuse yet, but IP is Tor/VPS/open proxy, user has no history of anonymous IP usage, and MFA was not completed | Containment recommended: revoke sessions, reset password, contact user for confirmation |
| **Benign True Positive (BTP)** | Alert correctly fired (IP IS anonymous) but verified as legitimate: user habitually uses commercial VPN (NordVPN, ExpressVPN), iCloud Private Relay, corporate privacy proxy, or is a known privacy-conscious user with baseline history of anonymous IP sign-ins | Close as BTP, document VPN provider, consider adding to named locations or risk policy exclusion |

## Key Differences from RB-0001, RB-0002, and RB-0003

1. **Unlike RB-0003 (Leaked Credentials) -- this alert HAS an IP address.** RB-0003 is an offline detection with no triggering sign-in and no IP. RB-0004 has a specific IP address, but that IP is intentionally anonymized. The investigation pivots on *classifying* the anonymous IP, not *finding* one.

2. **Unlike RB-0002 (Impossible Travel) -- this is a single sign-in event.** RB-0002 requires extracting and comparing TWO sign-in locations with geographic distance calculation. RB-0004 analyzes one sign-in from one anonymous IP. There is no distance or speed calculation.

3. **The unique investigation step is IP classification (Step 2).** No other runbook requires determining whether the source IP is Tor, commercial VPN, cloud proxy, hosting/VPS, or open proxy. This classification drives the entire investigation direction -- a Tor exit node is treated very differently from an iCloud Private Relay address.

4. **The false positive rate is VERY HIGH (~70-80%).** This is the highest FP rate of any Identity Protection risk detection. The primary driver is widespread commercial VPN adoption -- users running NordVPN, ExpressVPN, Surfshark, or similar services will trigger this alert on every sign-in. Organizations without VPN-aware Conditional Access policies will be flooded with these alerts. This is significantly higher than RB-0002 (~60-70% FP) and RB-0001 (~50-60% FP).

5. **Non-interactive sign-in check (Step 6) is critical.** When an attacker uses anonymous infrastructure, they often maintain access through non-interactive token refresh from the same anonymous IP. Checking AADNonInteractiveUserSignInLogs for the anonymous IP is essential to detect ongoing access that the attacker may maintain even after the initial sign-in alert.

6. **Baseline comparison focuses on anonymous IP history.** Unlike RB-0001 (which baselines location + device + browser) or RB-0002 (which baselines travel patterns), RB-0004's baseline specifically checks whether the user has a *pattern of using anonymous/VPN IPs*. A user who always signs in from NordVPN is fundamentally different from a user who has never used anonymous infrastructure.

## Estimated Investigation Time

| Scenario | Time |
|---|---|
| BTP quick close (known commercial VPN + user has anonymous IP baseline + no post-sign-in abuse) | 5-10 minutes |
| Standard investigation (all 7 steps, commercial VPN but no baseline or first-time anonymous IP) | 15-25 minutes |
| Complex investigation (Tor/VPS IP + no baseline + suspicious session + blast radius assessment) | 30-45 minutes |
| Confirmed compromise with containment (persistence found + evidence collection + remediation) | 60-90 minutes |
