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

### CI-Validated KQL

Every query is syntax-checked by Microsoft's official [Kusto.Language](https://www.nuget.org/packages/Microsoft.Azure.Kusto.Language) parser on each commit. Includes synthetic `datatable` tests and mandatory baseline comparisons.

</div>

</div>

---

## Quick Start

<div class="kql-steps" markdown>

<div class="kql-step" markdown>

<span class="kql-step-icon">:material-magnify:</span>

#### Find your alert

Browse the [Runbook Gallery](runbooks/gallery.md) or search by alert name, MITRE tactic, or severity.

</div>

<div class="kql-step" markdown>

<span class="kql-step-icon">:material-clipboard-check-outline:</span>

#### Check prerequisites

Each runbook lists required log sources, license tiers, and RBAC roles needed.

</div>

<div class="kql-step" markdown>

<span class="kql-step-icon">:material-play-circle-outline:</span>

#### Run the investigation

Copy KQL queries into Sentinel Log Analytics and follow the decision tree.

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

{{ coverage_cards() }}

See [Log Sources](log-sources.md) for the full reference of supported Sentinel tables.

---

## Query Validation

<div class="kql-validation-section" markdown>

Every KQL query in this project is automatically validated using Microsoft's official **Kusto.Language** parser — the same engine that powers Azure Data Explorer and Sentinel. This runs on every commit via [GitHub Actions CI](https://github.com/semihtut/kql-incident-response/actions).

<div class="kql-validation-stats" markdown>

| | |
|---|---|
| :material-check-circle:{ .kql-validated-icon } **{{ stats.query_count }} queries validated** | across {{ stats.runbook_count }} runbooks |
| :material-cog:{ .kql-validated-icon } **Validation engine** | [Microsoft.Azure.Kusto.Language](https://www.nuget.org/packages/Microsoft.Azure.Kusto.Language) (offline, no cluster required) |
| :material-sync:{ .kql-validated-icon } **Runs on** | Every push and pull request |

</div>

!!! note "Found a syntax issue?"
    While all queries pass the official KQL parser, minor issues may still exist in edge cases — such as deprecated functions or Sentinel-specific operators not covered by the offline parser. If you encounter a query that doesn't run in your environment, please [open an issue](https://github.com/semihtut/kql-incident-response/issues) or submit a PR. Fixes are usually a one-line change.

</div>

---

<div class="kql-cta" markdown>

## Contribute

Help build the most comprehensive open-source KQL incident response library. We need security analysts, KQL engineers, and threat intel researchers.

[Contributing Guide](contributing.md){ .kql-btn .kql-btn-primary }

</div>
