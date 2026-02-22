# Investigation Flow - Leaked Credentials (RB-0003)

> **Author:** Arina (IR Architect)
> **Reviewed by:** Leo (Coordinator)
> **Version:** 1.0

## Decision Tree

```
LEAKED CREDENTIALS RISK EVENT RECEIVED
│
├─ Step 1: Extract the leaked credential risk event
│   ├─ RiskEventType == "leakedCredentials" found? → Continue
│   └─ Not found? → Check for "unfamiliarFeatures" or other risk types, may be misclassified
│
├─ Step 2: User risk state and password timeline
│   ├─ Password changed AFTER leak detection? → Lower urgency (but still investigate)
│   ├─ Password NOT changed since leak? → HIGH urgency → Step 3 immediately
│   └─ User is already "confirmedCompromised"? → Skip to Containment
│
├─ Step 3: Baseline Comparison - Establish Normal Sign-In Pattern (30 days) [MANDATORY]
│   ├─ User has consistent sign-in pattern? → Use as reference for anomaly detection
│   ├─ New account with <7 days of history? → Flag as additional risk (no baseline)
│   └─ Account inactive (no sign-ins in 30 days)? → Lower risk but still reset password
│
├─ Step 4: Anomalous sign-in detection (post-leak window)
│   ├─ Sign-ins from new country/IP not in baseline? → HIGH concern → Step 5
│   ├─ Sign-ins from new device/browser? → MEDIUM concern → Step 5
│   ├─ Failed sign-ins from unknown IPs? → Credential being tested → Step 5
│   ├─ Successful sign-in without MFA from unknown IP? → CRITICAL → Step 5 + Containment
│   └─ No anomalous sign-ins found? → Step 6 (still check post-leak activity)
│
├─ Step 5: Post-sign-in activity (blast radius)
│   ├─ Inbox rules / forwarding created? → CONFIRMED BEC → Containment
│   ├─ MFA method registered from anomalous IP? → CONFIRMED persistence → Containment
│   ├─ OAuth app consented? → CONFIRMED persistence → Containment
│   ├─ Bulk data access from anomalous IP? → Data exposure → Containment + data loss assessment
│   └─ No suspicious activity → Step 6
│
├─ Step 6: Credential exposure assessment
│   ├─ User has MFA enforced? → Risk mitigated (attacker can't bypass MFA with just password)
│   ├─ User has legacy auth allowed? → HIGH risk (legacy auth bypasses MFA)
│   ├─ User is admin/privileged role? → ESCALATE regardless of other findings
│   └─ User has no MFA? → CRITICAL → Containment + enforce MFA
│
└─ Step 7: IP reputation (anomalous sign-in IPs, if any)
    ├─ Anomalous IP in TI feeds → HIGH confidence → Containment
    ├─ Anomalous IP is known credential-testing infra → Moderate concern
    ├─ Anomalous IP used by other org users → LOWER concern (shared VPN)
    └─ No anomalous IPs found → Close with password reset
```

## Classification Matrix

| Classification | Key Criteria | Action |
|---|---|---|
| **True Positive - Confirmed Compromise** | Anomalous sign-in + post-sign-in persistence OR successful sign-in without MFA from unknown IP | Immediate containment |
| **True Positive - Credential Exposed** | Leaked credential confirmed but no evidence of unauthorized use (yet). Password not changed. | Force password reset + enable MFA |
| **True Positive - Mitigated** | Leaked credential confirmed but password already changed or MFA blocks unauthorized access | Document, monitor for 7 days |
| **Benign True Positive** | Old leak, password already rotated, user has MFA, no anomalous activity | Close as BTP, confirm MFA status |

## Key Differences from RB-0001 and RB-0002

1. **No triggering sign-in event** - Unlike RB-0001/RB-0002, this alert is NOT triggered by a sign-in. It's an offline detection from dark web credential matching
2. **Offline detection** - Can fire hours or days after the actual breach/leak. Detection timing is always "offline"
3. **No geographic data in the alert** - The risk event itself has no IP or location. Investigation must SEARCH for anomalous sign-ins
4. **Password timeline is critical** - Must determine if the password was changed after the leak detection
5. **MFA status is decisive** - If user has MFA enforced, the leaked password alone cannot grant access
6. **Focus shifts to proactive hunting** - Instead of analyzing a known bad sign-in, we hunt for any sign of credential usage
7. **Credential stuffing correlation** - Same credentials may be tested across multiple accounts

## Estimated Investigation Time

| Scenario | Time |
|---|---|
| Quick close (password already changed + MFA active + no anomalous sign-ins) | 5-10 minutes |
| Standard investigation (all 7 steps, no compromise found) | 20-30 minutes |
| Confirmed compromise with containment | 45-60 minutes |
| Multi-account credential leak (same breach affecting multiple users) | 90-120 minutes |
