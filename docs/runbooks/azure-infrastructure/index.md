# Azure Infrastructure Runbooks

Investigation runbooks for Azure control plane and data plane alerts from Defender for Cloud, Defender for Key Vault, and Azure resource logs.

{% set cat_runbooks = categories['azure-infrastructure'].runbooks %}
{% if cat_runbooks %}
## Published Runbooks

| ID | Alert Name | Severity | Key Log Sources |
|----|-----------|----------|-----------------|
{% for rb in cat_runbooks %}
| {{ rb.id }} | [{{ rb.title }}]({{ rb.file_stem }}.md) | {{ rb.severity | capitalize }} | {{ rb.key_log_sources | join(', ') }} |
{% endfor %}

{% endif %}
## Planned Runbooks

| Alert Name | Source Product | Priority |
|-----------|---------------|----------|
| ~~Mass secret retrieval from Key Vault~~ | ~~Defender for Key Vault~~ | ~~Tier 3~~ (completed: RB-0007) |
| Storage account public exposure | Defender for Cloud | Tier 3 |
| Subscription hijacking | Sentinel Analytics | Tier 3 |
| Cryptomining resource deployment | Defender for Cloud | Tier 3 |
| NSG/firewall rule tampering | Sentinel Analytics | Tier 3 |
| Unusual role assignment (RBAC) | Sentinel Analytics | Tier 3 |
| Resource group deletion | Sentinel Analytics | Tier 3 |

## Key Log Sources

- **AzureDiagnostics** - Resource-level data plane logs, including Key Vault operations (Free + ingestion cost)
- **AzureActivity** - Azure control plane (ARM) operations (Free)
- **AzureMetrics** - Performance and health metrics (Free)
- **SecurityAlert** - Defender for Cloud / Defender for Key Vault alerts (Sentinel)
- **SecurityRecommendation** - Security posture recommendations (Defender for Cloud)

See [Log Sources Reference](../../log-sources.md) for full details.
