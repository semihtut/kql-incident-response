# Runbook Gallery

Browse all incident response runbooks. Filter by severity or MITRE ATT&CK tactic.

<div class="gallery-filters" markdown>
  <strong style="line-height: 2;">Severity:</strong>
  <button class="filter-btn active" data-group="severity" data-filter="all">All</button>
  <button class="filter-btn" data-group="severity" data-filter="critical">Critical</button>
  <button class="filter-btn" data-group="severity" data-filter="high">High</button>
  <button class="filter-btn" data-group="severity" data-filter="medium">Medium</button>
  <button class="filter-btn" data-group="severity" data-filter="low">Low</button>
</div>

<div class="gallery-filters" markdown>
  <strong style="line-height: 2;">Tactic:</strong>
  <button class="filter-btn active" data-group="tactic" data-filter="all">All</button>
  <button class="filter-btn" data-group="tactic" data-filter="initial-access">Initial Access</button>
  <button class="filter-btn" data-group="tactic" data-filter="persistence">Persistence</button>
  <button class="filter-btn" data-group="tactic" data-filter="priv-esc">Privilege Escalation</button>
  <button class="filter-btn" data-group="tactic" data-filter="defense-evasion">Defense Evasion</button>
  <button class="filter-btn" data-group="tactic" data-filter="cred-access">Credential Access</button>
  <button class="filter-btn" data-group="tactic" data-filter="lateral-movement">Lateral Movement</button>
  <button class="filter-btn" data-group="tactic" data-filter="collection">Collection</button>
</div>

<div class="runbook-gallery" markdown>

<a class="runbook-card" href="../runbooks/identity/unfamiliar-sign-in-properties/" data-severity="medium" data-tactics="initial-access,persistence,priv-esc,defense-evasion,cred-access,lateral-movement,collection" markdown>
<div class="runbook-card-header">
  <span class="severity-badge severity-medium">Medium</span>
  <span class="runbook-card-id">RB-0001</span>
</div>

### Unfamiliar Sign-In Properties

<div class="runbook-card-description">
Entra ID Identity Protection risk detection. Covers credential compromise via valid accounts, post-access persistence (inbox rules, MFA manipulation, OAuth consent), and blast radius assessment.
</div>

<div class="runbook-card-meta">
  <span class="mitre-tag mitre-initial-access">Initial Access</span>
  <span class="mitre-tag mitre-persistence">Persistence</span>
  <span class="mitre-tag mitre-priv-esc">Priv Esc</span>
  <span class="mitre-tag mitre-defense-evasion">Defense Evasion</span>
  <span class="mitre-tag mitre-cred-access">Cred Access</span>
  <span class="mitre-tag mitre-lateral-movement">Lateral Movement</span>
  <span class="mitre-tag mitre-collection">Collection</span>
</div>

<div class="runbook-card-footer">
  <span class="tier-badge">Tier 1 - Identity</span>
  <span class="status-badge status-complete">Complete</span>
</div>
</a>

<div class="runbook-card" data-severity="medium" data-tactics="initial-access,cred-access" style="opacity: 0.5;" markdown>
<div class="runbook-card-header">
  <span class="severity-badge severity-medium">Medium</span>
  <span class="runbook-card-id">RB-0002</span>
</div>

### Impossible Travel Activity

<div class="runbook-card-description">
Identity Protection risk detection for sign-ins from geographically distant locations within an impossible timeframe.
</div>

<div class="runbook-card-meta">
  <span class="mitre-tag mitre-initial-access">Initial Access</span>
  <span class="mitre-tag mitre-cred-access">Cred Access</span>
</div>

<div class="runbook-card-footer">
  <span class="tier-badge">Tier 1 - Identity</span>
  <span class="status-badge status-planned">Planned</span>
</div>
</div>

<div class="runbook-card" data-severity="high" data-tactics="initial-access,cred-access" style="opacity: 0.5;" markdown>
<div class="runbook-card-header">
  <span class="severity-badge severity-high">High</span>
  <span class="runbook-card-id">RB-0003</span>
</div>

### MFA Fatigue Attack

<div class="runbook-card-description">
Detects MFA push notification bombing attacks where adversaries repeatedly trigger MFA prompts hoping the user approves.
</div>

<div class="runbook-card-meta">
  <span class="mitre-tag mitre-initial-access">Initial Access</span>
  <span class="mitre-tag mitre-cred-access">Cred Access</span>
</div>

<div class="runbook-card-footer">
  <span class="tier-badge">Tier 1 - Identity</span>
  <span class="status-badge status-planned">Planned</span>
</div>
</div>

<div class="runbook-card" data-severity="high" data-tactics="cred-access,lateral-movement" style="opacity: 0.5;" markdown>
<div class="runbook-card-header">
  <span class="severity-badge severity-high">High</span>
  <span class="runbook-card-id">RB-0004</span>
</div>

### Password Spray Detection

<div class="runbook-card-description">
Detects distributed password spray attacks across multiple accounts using Identity Protection and SigninLogs analysis.
</div>

<div class="runbook-card-meta">
  <span class="mitre-tag mitre-cred-access">Cred Access</span>
  <span class="mitre-tag mitre-lateral-movement">Lateral Movement</span>
</div>

<div class="runbook-card-footer">
  <span class="tier-badge">Tier 1 - Identity</span>
  <span class="status-badge status-planned">Planned</span>
</div>
</div>

<div class="runbook-card" data-severity="critical" data-tactics="cred-access,collection,exfiltration" style="opacity: 0.5;" markdown>
<div class="runbook-card-header">
  <span class="severity-badge severity-critical">Critical</span>
  <span class="runbook-card-id">RB-0005</span>
</div>

### Mass Secret Retrieval from Key Vault

<div class="runbook-card-description">
Detects mass enumeration and retrieval of secrets from Azure Key Vault, a common post-compromise activity for credential harvesting.
</div>

<div class="runbook-card-meta">
  <span class="mitre-tag mitre-cred-access">Cred Access</span>
  <span class="mitre-tag mitre-collection">Collection</span>
  <span class="mitre-tag mitre-exfiltration">Exfiltration</span>
</div>

<div class="runbook-card-footer">
  <span class="tier-badge">Tier 3 - Azure Infra</span>
  <span class="status-badge status-planned">Planned</span>
</div>
</div>

</div>
