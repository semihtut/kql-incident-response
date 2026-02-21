# MITRE ATT&CK Coverage

Visual coverage map of MITRE ATT&CK techniques across all published runbooks.

## Coverage Overview

<div class="coverage-bar">
  <div class="coverage-bar-fill coverage-covered" style="width: 50%">7 Covered</div>
  <div class="coverage-bar-fill coverage-gap" style="width: 50%">7 Gaps</div>
</div>

| Metric | Count |
|--------|-------|
| Tactics covered | **7** of 14 |
| Techniques mapped | **15** |
| Runbooks published | **1** |

---

## ATT&CK Matrix

<span class="mitre-technique" style="display:inline-block; margin-right: 1rem;">:material-check-circle:{ style="color: var(--severity-info)" } Covered by runbook</span>
<span class="mitre-technique" style="display:inline-block;">:material-circle-outline:{ style="color: #9E9E9E" } Planned</span>

<div class="mitre-matrix" markdown>

<div class="mitre-column" markdown>
<div class="mitre-column-header" style="background: var(--mitre-recon);">Reconnaissance</div>
<div class="mitre-technique mitre-gap">
<span class="mitre-technique-id">TA0043</span>
No techniques mapped yet
</div>
</div>

<div class="mitre-column" markdown>
<div class="mitre-column-header" style="background: var(--mitre-resource-dev);">Resource Dev</div>
<div class="mitre-technique mitre-gap">
<span class="mitre-technique-id">TA0042</span>
No techniques mapped yet
</div>
</div>

<div class="mitre-column" markdown>
<div class="mitre-column-header" style="background: var(--mitre-initial-access);">Initial Access</div>
<a class="mitre-technique mitre-covered" href="runbooks/identity/unfamiliar-sign-in-properties/">
<span class="mitre-technique-id">T1078.004</span>
Valid Accounts: Cloud Accounts
</a>
<a class="mitre-technique mitre-covered" href="runbooks/identity/unfamiliar-sign-in-properties/">
<span class="mitre-technique-id">T1539</span>
Steal Web Session Cookie
</a>
</div>

<div class="mitre-column" markdown>
<div class="mitre-column-header" style="background: var(--mitre-execution);">Execution</div>
<div class="mitre-technique mitre-gap">
<span class="mitre-technique-id">TA0002</span>
No techniques mapped yet
</div>
</div>

<div class="mitre-column" markdown>
<div class="mitre-column-header" style="background: var(--mitre-persistence);">Persistence</div>
<a class="mitre-technique mitre-covered" href="runbooks/identity/unfamiliar-sign-in-properties/">
<span class="mitre-technique-id">T1098</span>
Account Manipulation
</a>
<a class="mitre-technique mitre-covered" href="runbooks/identity/unfamiliar-sign-in-properties/">
<span class="mitre-technique-id">T1556.006</span>
Modify Auth Process: MFA
</a>
<a class="mitre-technique mitre-covered" href="runbooks/identity/unfamiliar-sign-in-properties/">
<span class="mitre-technique-id">T1564.008</span>
Email Hiding Rules
</a>
</div>

<div class="mitre-column" markdown>
<div class="mitre-column-header" style="background: var(--mitre-priv-esc);">Privilege Esc</div>
<a class="mitre-technique mitre-covered" href="runbooks/identity/unfamiliar-sign-in-properties/">
<span class="mitre-technique-id">T1078.004</span>
Valid Accounts: Cloud
</a>
</div>

<div class="mitre-column" markdown>
<div class="mitre-column-header" style="background: var(--mitre-defense-evasion);">Defense Evasion</div>
<a class="mitre-technique mitre-covered" href="runbooks/identity/unfamiliar-sign-in-properties/">
<span class="mitre-technique-id">T1556.006</span>
Modify Auth Process: MFA
</a>
<a class="mitre-technique mitre-covered" href="runbooks/identity/unfamiliar-sign-in-properties/">
<span class="mitre-technique-id">T1564.008</span>
Email Hiding Rules
</a>
</div>

<div class="mitre-column" markdown>
<div class="mitre-column-header" style="background: var(--mitre-cred-access);">Credential Access</div>
<a class="mitre-technique mitre-covered" href="runbooks/identity/unfamiliar-sign-in-properties/">
<span class="mitre-technique-id">T1110.003</span>
Password Spraying
</a>
<a class="mitre-technique mitre-covered" href="runbooks/identity/unfamiliar-sign-in-properties/">
<span class="mitre-technique-id">T1110.004</span>
Credential Stuffing
</a>
<a class="mitre-technique mitre-covered" href="runbooks/identity/unfamiliar-sign-in-properties/">
<span class="mitre-technique-id">T1528</span>
Steal App Access Token
</a>
</div>

<div class="mitre-column" markdown>
<div class="mitre-column-header" style="background: var(--mitre-discovery);">Discovery</div>
<div class="mitre-technique mitre-gap">
<span class="mitre-technique-id">TA0007</span>
No techniques mapped yet
</div>
</div>

<div class="mitre-column" markdown>
<div class="mitre-column-header" style="background: var(--mitre-lateral-movement);">Lateral Movement</div>
<a class="mitre-technique mitre-covered" href="runbooks/identity/unfamiliar-sign-in-properties/">
<span class="mitre-technique-id">T1534</span>
Internal Spearphishing
</a>
</div>

<div class="mitre-column" markdown>
<div class="mitre-column-header" style="background: var(--mitre-collection);">Collection</div>
<a class="mitre-technique mitre-covered" href="runbooks/identity/unfamiliar-sign-in-properties/">
<span class="mitre-technique-id">T1114.003</span>
Email Forwarding Rule
</a>
<a class="mitre-technique mitre-covered" href="runbooks/identity/unfamiliar-sign-in-properties/">
<span class="mitre-technique-id">T1530</span>
Data from Cloud Storage
</a>
</div>

<div class="mitre-column" markdown>
<div class="mitre-column-header" style="background: var(--mitre-exfiltration);">Exfiltration</div>
<div class="mitre-technique mitre-gap">
<span class="mitre-technique-id">TA0010</span>
No techniques mapped yet
</div>
</div>

<div class="mitre-column" markdown>
<div class="mitre-column-header" style="background: var(--mitre-c2);">Command & Control</div>
<div class="mitre-technique mitre-gap">
<span class="mitre-technique-id">TA0011</span>
No techniques mapped yet
</div>
</div>

<div class="mitre-column" markdown>
<div class="mitre-column-header" style="background: var(--mitre-impact);">Impact</div>
<div class="mitre-technique mitre-gap">
<span class="mitre-technique-id">TA0040</span>
No techniques mapped yet
</div>
</div>

</div>

---

## Technique Detail

All techniques currently mapped from [RB-0001: Unfamiliar Sign-In Properties](runbooks/identity/unfamiliar-sign-in-properties.md):

| Technique ID | Technique Name | Tactic | Confidence |
|-------------|----------------|--------|------------|
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | <span class="severity-badge severity-info">Confirmed</span> |
| T1098 | Account Manipulation | Persistence | <span class="severity-badge severity-info">Confirmed</span> |
| T1110.003 | Brute Force: Password Spraying | Credential Access | <span class="severity-badge severity-medium">Probable</span> |
| T1110.004 | Brute Force: Credential Stuffing | Credential Access | <span class="severity-badge severity-medium">Probable</span> |
| T1114.003 | Email Collection: Email Forwarding Rule | Collection | <span class="severity-badge severity-info">Confirmed</span> |
| T1528 | Steal Application Access Token | Credential Access | <span class="severity-badge severity-info">Confirmed</span> |
| T1530 | Data from Cloud Storage Object | Collection | <span class="severity-badge severity-info">Confirmed</span> |
| T1534 | Internal Spearphishing | Lateral Movement | <span class="severity-badge severity-info">Confirmed</span> |
| T1539 | Steal Web Session Cookie | Initial Access | <span class="severity-badge severity-low">Possible</span> |
| T1556.006 | Modify Authentication Process: MFA | Persistence, Defense Evasion | <span class="severity-badge severity-info">Confirmed</span> |
| T1564.008 | Hide Artifacts: Email Hiding Rules | Persistence, Defense Evasion | <span class="severity-badge severity-info">Confirmed</span> |

---

## Planned Coverage

### Tier 1 (Identity)

- MFA fatigue / MFA bombing
- Impossible travel detection
- Suspicious browser sign-in
- Password spray detection
- Risky sign-in from anonymous IP

### Tier 2 (Lateral Movement & Escalation)

- Privilege escalation via PIM abuse
- OAuth consent grant abuse
- Mailbox delegation abuse
- Cross-tenant access anomaly
- Service principal compromise

### Tier 3 (Cloud Infrastructure)

- Mass secret retrieval from Key Vault
- Storage account public exposure
- Subscription hijacking
- Cryptomining detection
- NSG/firewall rule tampering
