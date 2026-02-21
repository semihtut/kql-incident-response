# Investigation Flow - Impossible Travel Activity (RB-0002)

> **Author:** Arina (IR Architect)
> **Reviewed by:** Leo (Coordinator)
> **Version:** 1.0

## Decision Tree

```
IMPOSSIBLE TRAVEL ALERT RECEIVED
│
├─ Step 1: Extract BOTH sign-in records
│   ├─ Found 2 sign-ins from different IPs? → Continue
│   └─ Only 1 sign-in found? → Expand lookback to 24h, check non-interactive logs
│
├─ Step 2: Calculate distance & travel speed
│   ├─ Same DeviceId for both? → HIGH probability of VPN FP → Step 3
│   ├─ Speed > 900 km/h + different devices? → IMPOSSIBLE → Step 4 + Step 5
│   ├─ Speed 500-900 km/h? → HIGHLY UNLIKELY → Step 3 + Step 4
│   ├─ Speed 200-500 km/h? → UNLIKELY → Step 3
│   └─ Speed < 200 km/h? → PLAUSIBLE → Step 3 (may quick close)
│
├─ Step 3: Travel pattern baseline (30 days) [MANDATORY]
│   ├─ Both IPs in baseline? → Lower concern
│   ├─ Only IP1 in baseline? → IP2 is new → higher concern
│   ├─ Neither IP in baseline? → Very high concern (new account or both compromised)
│   └─ User has frequent VPN switching pattern? → Weight toward FP
│
├─ Step 4: Device & session fingerprint analysis
│   ├─ Same DeviceId → VPN/proxy confirmed → Step 7 (quick close candidate)
│   ├─ Same SessionId from different IPs → TOKEN REPLAY → Step 5 immediately
│   ├─ Different device + different OS → HIGH RISK → Step 5
│   └─ Different device but same OS/browser → MEDIUM RISK → Step 5
│
├─ Step 5: Token replay check (T1550.004)
│   ├─ Non-interactive sign-ins from anomalous IP? → CONFIRMED token replay → Containment
│   ├─ Same SessionId from multiple IPs? → CONFIRMED session hijacking → Containment
│   └─ No token evidence → Step 6
│
├─ Step 6: Post-sign-in activity (blast radius)
│   ├─ Inbox rules / forwarding created? → CONFIRMED BEC → Containment
│   ├─ MFA method registered? → CONFIRMED persistence → Containment
│   ├─ OAuth app consented? → CONFIRMED persistence → Containment
│   ├─ Bulk data access? → Data exposure → Containment + data loss assessment
│   └─ No suspicious activity → Step 7
│
└─ Step 7: IP reputation (BOTH IPs)
    ├─ Anomalous IP in TI feeds → HIGH confidence → Containment
    ├─ Anomalous IP is hosting/VPN provider → Moderate concern
    ├─ Anomalous IP used by other org users → LOWER concern (shared VPN)
    └─ Clean IPs + no other indicators → Close as FP
```

## Classification Matrix

| Classification | Key Criteria | Action |
|---|---|---|
| **True Positive - Confirmed Compromise** | Token replay confirmed OR post-sign-in persistence found OR TI-matched IP + different devices | Immediate containment |
| **True Positive - Likely Compromise** | Speed > 900 + different devices + new country, but no confirmed post-sign-in abuse | Containment recommended, contact user |
| **Benign True Positive** | Alert correctly fired but verified as VPN/proxy (same DeviceId) or legitimate travel | Close as BTP, document reason |
| **False Positive** | Same DeviceId + known VPN IP + user has VPN switching history | Close as FP, add VPN IPs to trusted locations |

## Key Differences from RB-0001

1. **Two sign-ins required** - Must extract and analyze BOTH endpoints of the impossible travel
2. **Geographic calculation** - Uses `geo_distance_2points()` for precise distance and speed
3. **DeviceId comparison** - The #1 FP indicator (same device = VPN routing)
4. **Token replay check** - New Step 5 not present in RB-0001, covers T1550.004
5. **Dual IP reputation** - Must check BOTH IPs, not just one
6. **Higher FP rate** - ~60-70% of these alerts are VPN/proxy false positives

## Estimated Investigation Time

| Scenario | Time |
|---|---|
| Quick close (same DeviceId + known VPN) | 5-10 minutes |
| Standard investigation (all 7 steps) | 30-45 minutes |
| Confirmed compromise with containment | 60-90 minutes |
| Token replay with full blast radius assessment | 90-120 minutes |
