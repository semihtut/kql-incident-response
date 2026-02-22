---
hide:
  - toc
---

<div class="kql-hero" markdown>

# KQL Incident Response Playbooks

<p class="tagline">Cloud IR, powered by KQL</p>

<div class="kql-hero-stats">
  <div class="kql-stat">
    <span class="number">{{ stats.runbook_count }}</span>
    <span class="label">Runbooks</span>
  </div>
  <div class="kql-stat">
    <span class="number">{{ stats.technique_count }}</span>
    <span class="label">MITRE Techniques</span>
  </div>
  <div class="kql-stat">
    <span class="number">{{ stats.table_count }}</span>
    <span class="label">Log Tables</span>
  </div>
  <div class="kql-stat">
    <span class="number">{{ stats.tactic_count }}</span>
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
{% for rb in runbooks | sort(attribute='id', reverse=true) %}
{% if loop.index <= 2 %}
  <a class="runbook-card" href="runbooks/{{ rb.category_slug }}/{{ rb.file_stem }}/">
    <div class="runbook-card-header">
      <span class="runbook-card-id">{{ rb.id }}</span>
      <span class="severity-badge severity-{{ rb.severity }}">{{ rb.severity | capitalize }}</span>
    </div>
    <h3>{{ rb.title }}</h3>
    <div class="runbook-card-description">
      {{ rb.description | trim | truncate(200) }}
    </div>
    <div class="runbook-card-footer">
{% for slug in rb.tactic_slugs[:5] %}
      <span class="mitre-tag mitre-{{ slug }}">{{ tactic_short[slug] }}</span>
{% endfor %}
      <span class="tier-badge">Tier {{ rb.tier }}</span>
      <span class="status-badge {{ rb.status_class }}">{{ rb.display_status }}</span>
    </div>
  </a>
{% endif %}
{% endfor %}
</div>

---

## Coverage

| Category | Runbooks | Status |
|----------|----------|--------|
{% for slug in ['identity', 'endpoint', 'email', 'cloud-apps', 'azure-infrastructure', 'okta'] %}
{% if categories[slug].count > 0 %}
| [{{ categories[slug].name }}](runbooks/{{ slug }}/index.md) | {{ categories[slug].count }} completed | :material-check-circle:{ .severity-info } Active |
{% else %}
| [{{ categories[slug].name }}](runbooks/{{ slug }}/index.md) | Planned | Tier 2 |
{% endif %}
{% endfor %}

See [Log Sources](log-sources.md) for the full reference of supported Sentinel tables.

---

<div class="kql-cta" markdown>

## Contribute

Help build the most comprehensive open-source KQL incident response library. We need security analysts, KQL engineers, and threat intel researchers.

[Contributing Guide](contributing.md){ .kql-btn .kql-btn-primary }

</div>
