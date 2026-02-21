---
hide:
  - toc
---

<div class="kql-hero" markdown>

# KQL Incident Response Playbooks

<p class="tagline">Cloud IR, powered by KQL</p>

<div class="kql-hero-stats">
  <div class="kql-stat">
    <span class="number">2</span>
    <span class="label">Runbooks</span>
  </div>
  <div class="kql-stat">
    <span class="number">16</span>
    <span class="label">MITRE Techniques</span>
  </div>
  <div class="kql-stat">
    <span class="number">43</span>
    <span class="label">Log Tables</span>
  </div>
  <div class="kql-stat">
    <span class="number">7</span>
    <span class="label">Tactics Covered</span>
  </div>
</div>

<div class="kql-hero-actions">
  <a href="runbooks/" class="kql-btn kql-btn-primary">Browse Runbooks</a>
  <a href="getting-started/" class="kql-btn kql-btn-outline">Get Started</a>
</div>

</div>

<div class="kql-features" markdown>

<div class="kql-feature-card" markdown>

<span class="icon">:material-book-open-page-variant:</span>

### Structured Runbooks

Step-by-step investigation guides with KQL queries, decision trees, and containment actions. Every runbook follows a consistent format so analysts know exactly where to look.

</div>

<div class="kql-feature-card" markdown>

<span class="icon">:material-shield-check:</span>

### MITRE ATT&CK Mapped

Every runbook maps to MITRE ATT&CK tactics and techniques with confidence levels. Track your detection coverage across the full attack lifecycle.

</div>

<div class="kql-feature-card" markdown>

<span class="icon">:material-test-tube:</span>

### Battle-Tested KQL

Production-grade queries validated with synthetic `datatable` tests. Every query includes baseline comparison to distinguish real threats from noise.

</div>

</div>

---

## Quick Start

<div class="kql-steps" markdown>

<div class="kql-step" markdown>
<div class="kql-step-number">1</div>
<div class="kql-step-content" markdown>

#### Find your alert

Browse the [Runbook Gallery](runbooks/gallery.md) or search by alert name, MITRE tactic, or severity.

</div>
</div>

<div class="kql-step" markdown>
<div class="kql-step-number">2</div>
<div class="kql-step-content" markdown>

#### Check prerequisites

Each runbook lists required log sources, license tiers, and RBAC roles needed.

</div>
</div>

<div class="kql-step" markdown>
<div class="kql-step-number">3</div>
<div class="kql-step-content" markdown>

#### Run the investigation

Copy KQL queries into Sentinel Log Analytics and follow the decision tree.

</div>
</div>

</div>

---

## Latest Runbooks

<div class="latest-runbooks">
  <a class="runbook-card" href="runbooks/identity/impossible-travel-activity/">
    <div class="runbook-card-header">
      <span class="runbook-card-id">RB-0002</span>
      <span class="severity-badge severity-medium">Medium</span>
    </div>
    <h3>Impossible Travel Activity</h3>
    <div class="runbook-card-description">
      Entra ID Identity Protection risk detection for geographically impossible sign-in pairs. Covers VPN false positive triage, token replay detection (T1550.004), and blast radius assessment.
    </div>
    <div class="runbook-card-footer">
      <span class="mitre-tag mitre-initial-access">Initial Access</span>
      <span class="mitre-tag mitre-defense-evasion">Def Evasion</span>
      <span class="mitre-tag mitre-cred-access">Cred Access</span>
      <span class="mitre-tag mitre-persistence">Persistence</span>
      <span class="tier-badge">Tier 1</span>
      <span class="status-badge status-complete">Complete</span>
    </div>
  </a>
  <a class="runbook-card" href="runbooks/identity/unfamiliar-sign-in-properties/">
    <div class="runbook-card-header">
      <span class="runbook-card-id">RB-0001</span>
      <span class="severity-badge severity-medium">Medium</span>
    </div>
    <h3>Unfamiliar Sign-In Properties</h3>
    <div class="runbook-card-description">
      Entra ID Identity Protection risk detection. Covers credential compromise via valid accounts, post-access persistence, inbox rules, MFA manipulation, and OAuth consent abuse.
    </div>
    <div class="runbook-card-footer">
      <span class="mitre-tag mitre-initial-access">Initial Access</span>
      <span class="mitre-tag mitre-persistence">Persistence</span>
      <span class="mitre-tag mitre-cred-access">Cred Access</span>
      <span class="mitre-tag mitre-lateral-movement">Lateral Mov</span>
      <span class="tier-badge">Tier 1</span>
      <span class="status-badge status-complete">Complete</span>
    </div>
  </a>
</div>

---

## Coverage

| Category | Runbooks | Status |
|----------|----------|--------|
| [Identity](runbooks/identity/index.md) | 2 completed | :material-check-circle:{ .severity-info } Active |
| [Endpoint](runbooks/endpoint/index.md) | Planned | Tier 2 |
| [Email](runbooks/email/index.md) | Planned | Tier 2 |
| [Cloud Apps](runbooks/cloud-apps/index.md) | Planned | Tier 2 |
| [Azure Infrastructure](runbooks/azure-infrastructure/index.md) | Planned | Tier 3 |
| [Okta](runbooks/okta/index.md) | Planned | Tier 2 |

See [Log Sources](log-sources.md) for the full reference of 43 supported Sentinel tables across 11 categories.

---

<div class="kql-cta" markdown>

## Contribute

Help build the most comprehensive open-source KQL incident response library. We need security analysts, KQL engineers, and threat intel researchers.

[Contributing Guide](contributing.md){ .kql-btn .kql-btn-primary }

</div>
