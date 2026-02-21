# Azure Infrastructure Runbooks

Investigation runbooks for Azure control plane and data plane alerts from Defender for Cloud and Azure resource logs.

!!! info "Coming Soon"
    Azure Infrastructure runbooks are planned for Tier 3 development. Check back for updates.

## Planned Runbooks

| Alert Name | Source Product | Priority |
|-----------|---------------|----------|
| Mass secret retrieval from Key Vault | Defender for Cloud | Tier 3 |
| Storage account public exposure | Defender for Cloud | Tier 3 |
| Subscription hijacking | Sentinel Analytics | Tier 3 |
| Cryptomining resource deployment | Defender for Cloud | Tier 3 |
| NSG/firewall rule tampering | Sentinel Analytics | Tier 3 |
| Unusual role assignment (RBAC) | Sentinel Analytics | Tier 3 |
| Resource group deletion | Sentinel Analytics | Tier 3 |

## Key Log Sources

- **AzureActivity** - Azure control plane (ARM) operations (Free)
- **AzureDiagnostics** - Resource-level data plane logs (Free + ingestion cost)
- **AzureMetrics** - Performance and health metrics (Free)
- **SecurityAlert** - Defender for Cloud alerts (Sentinel)
- **SecurityRecommendation** - Security posture recommendations (Defender for Cloud)

See [Log Sources Reference](../../log-sources.md) for full details.
