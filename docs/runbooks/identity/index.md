# Identity Runbooks

Investigation runbooks for identity-based alerts from Microsoft Entra ID, Identity Protection, and Conditional Access.

## Published Runbooks

| ID | Alert Name | Severity | Key Log Sources |
|----|-----------|----------|-----------------|
| RB-0001 | [Unfamiliar Sign-In Properties](unfamiliar-sign-in-properties.md) | Medium | SigninLogs, AADUserRiskEvents, AADRiskyUsers, AuditLogs, OfficeActivity |

## Planned Runbooks

| Alert Name | Source Product | Priority |
|-----------|---------------|----------|
| Impossible travel activity | Identity Protection | Tier 1 |
| MFA fatigue attack | Identity Protection | Tier 1 |
| Suspicious browser sign-in | Identity Protection | Tier 1 |
| Anonymous IP address sign-in | Identity Protection | Tier 1 |
| Password spray detection | Identity Protection / Sentinel | Tier 1 |
| Atypical travel | Identity Protection | Tier 1 |
| Token anomaly detection | Identity Protection | Tier 1 |
| Leaked credentials | Identity Protection | Tier 1 |
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
