# Runbooks

KQL-based incident response runbooks organized by Microsoft security product category. Each runbook provides a complete investigation guide with step-by-step queries, explanations, MITRE ATT&CK mappings, and synthetic test data.

## Categories

| Category | Description | Runbooks |
|----------|-------------|----------|
{% for slug in ['identity', 'endpoint', 'email', 'cloud-apps', 'azure-infrastructure', 'okta'] %}
| [{{ categories[slug].name }}]({{ slug }}/index.md) | {{ category_descriptions[slug] }} | {{ categories[slug].count if categories[slug].count > 0 else 'Coming soon' }} |
{% endfor %}

## How Runbooks Are Structured

Every runbook follows a consistent format:

1. **Metadata** - Alert name, severity, MITRE ATT&CK mapping, log sources, license requirements
2. **Investigation Steps** - Ordered KQL queries with purpose, guidance, and decision points
3. **Baseline Comparison** - Statistical comparison against normal behavior patterns
4. **Containment Actions** - Specific remediation steps and commands
5. **Evidence Collection** - What to preserve for forensic analysis
6. **Sample Data** - Synthetic `datatable`-based test data for validation

## Runbook Index

| ID | Alert Name | Category | Severity | MITRE Tactics |
|----|-----------|----------|----------|---------------|
{% for rb in runbooks %}
| {{ rb.id }} | [{{ rb.title }}]({{ rb.category_slug }}/{{ rb.file_stem }}.md) | {{ rb.category_name }} | {{ rb.severity | capitalize }} | {{ rb.tactic_names | join(', ') }} |
{% endfor %}
