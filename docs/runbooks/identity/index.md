# Identity Runbooks

Investigation runbooks for identity-based alerts from Microsoft Entra ID, Identity Protection, and Conditional Access.

{% set cat_runbooks = categories['identity'].runbooks %}
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
| ~~MFA fatigue attack~~ | ~~Identity Protection~~ | ~~Tier 1~~ (completed: RB-0005) |
| Suspicious browser sign-in | Identity Protection | Tier 1 |
| ~~Password spray detection~~ | ~~Identity Protection / Sentinel~~ | ~~Tier 1~~ (completed: RB-0006) |
| Atypical travel | Identity Protection | Tier 1 |
| Token anomaly detection | Identity Protection | Tier 1 |
| Risky user confirmed compromised | Identity Protection | Tier 1 |
| Suspicious inbox forwarding rule | Sentinel Analytics | Tier 1 |

## Log Sources

Identity runbooks primarily use these tables:

- **SigninLogs** - Interactive user sign-in events (Entra ID Free)
- **AADNonInteractiveUserSignInLogs** - Non-interactive sign-ins (Entra ID P1+)
- **AADUserRiskEvents** - Identity Protection risk detections (Entra ID P2)
- **AADRiskyUsers** - Users flagged as risky (Entra ID P2)
- **AuditLogs** - Directory changes and role assignments (Entra ID Free)
- **IdentityInfo** - User enrichment data (Sentinel UEBA)
- **OfficeActivity** - Mailbox and file activity (M365 E3+)

See [Log Sources Reference](../../log-sources.md) for full details.
