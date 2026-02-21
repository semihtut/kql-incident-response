# Okta Runbooks

Investigation runbooks for Okta identity provider alerts ingested via the Microsoft Sentinel Okta connector.

!!! info "Coming Soon"
    Okta runbooks are planned for Tier 2 development. Check back for updates.

## Planned Runbooks

| Alert Name | Source Product | Priority |
|-----------|---------------|----------|
| Okta credential stuffing attack | Okta / Sentinel | Tier 2 |
| MFA factor manipulation | Okta / Sentinel | Tier 2 |
| Admin impersonation | Okta / Sentinel | Tier 2 |
| Session hijacking via cookie theft | Okta / Sentinel | Tier 2 |
| Suspicious API token usage | Okta / Sentinel | Tier 2 |
| Rate limit violation pattern | Okta / Sentinel | Tier 2 |

## Key Log Sources

- **Okta_CL** - Legacy custom log connector (Okta + Sentinel)
- **OktaSSO** - Native Sentinel connector, preview (Okta + Sentinel)
- **OktaV2_CL** - V2 custom log connector (Okta + Sentinel)

!!! note
    Your Okta table name depends on which Sentinel connector variant you deployed. Check your workspace for which table contains data. All three variants capture the same underlying Okta System Log events.

See [Log Sources Reference](../../log-sources.md) for full details.
