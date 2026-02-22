# Runbook Gallery

Browse all incident response runbooks. Filter by severity or MITRE ATT&CK tactic.

<div class="gallery-filters">
  <strong style="line-height: 2;">Severity:</strong>
  <button class="filter-btn active" data-group="severity" data-filter="all">All</button>
{% for sev in all_severities %}
  <button class="filter-btn" data-group="severity" data-filter="{{ sev }}">{{ sev | capitalize }}</button>
{% endfor %}
</div>

<div class="gallery-filters">
  <strong style="line-height: 2;">Tactic:</strong>
  <button class="filter-btn active" data-group="tactic" data-filter="all">All</button>
{% for slug in all_tactics %}
  <button class="filter-btn" data-group="tactic" data-filter="{{ slug }}">{{ tactic_short[slug] }}</button>
{% endfor %}
</div>

<div class="runbook-gallery">

{% for rb in all_runbooks %}
{% if rb.status == 'planned' %}
  <div class="runbook-card runbook-planned" data-severity="{{ rb.severity }}" data-tactics="{{ rb.tactic_slugs | join(',') }}">
{% else %}
  <a class="runbook-card" href="../{{ rb.category_slug }}/{{ rb.file_stem }}/" data-severity="{{ rb.severity }}" data-tactics="{{ rb.tactic_slugs | join(',') }}">
{% endif %}
    <div class="runbook-card-header">
      <span class="runbook-card-id">{{ rb.id }}</span>
      <span class="severity-badge severity-{{ rb.severity }}">{{ rb.severity | capitalize }}</span>
    </div>
    <h3>{{ rb.title }}</h3>
    <div class="runbook-card-description">
      {{ rb.description | trim }}
    </div>
    <div class="runbook-card-footer">
{% for slug in rb.tactic_slugs %}
      <span class="mitre-tag mitre-{{ slug }}">{{ tactic_short[slug] }}</span>
{% endfor %}
      <span class="tier-badge">Tier {{ rb.tier }}</span>
      <span class="status-badge {{ rb.status_class }}">{{ rb.display_status }}</span>
    </div>
{% if rb.status == 'planned' %}
  </div>
{% else %}
  </a>
{% endif %}

{% endfor %}
</div>
