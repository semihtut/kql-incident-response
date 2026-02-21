# Runbooks

KQL-based incident response runbooks organized by Microsoft security product category. Each runbook provides a complete investigation guide with step-by-step queries, explanations, MITRE ATT&CK mappings, and synthetic test data.

## Categories

| Category | Description | Runbooks |
|----------|-------------|----------|
| [Identity](identity/index.md) | Entra ID, Identity Protection, Conditional Access | 1 |
| [Endpoint](endpoint/index.md) | Defender for Endpoint, device-level threats | Coming soon |
| [Email](email/index.md) | Defender for Office 365, phishing, BEC | Coming soon |
| [Cloud Apps](cloud-apps/index.md) | Defender for Cloud Apps, SaaS threats | Coming soon |
| [Azure Infrastructure](azure-infrastructure/index.md) | Azure control/data plane, Key Vault, Storage | Coming soon |
| [Okta](okta/index.md) | Okta IdP via Sentinel connector | Coming soon |

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
| RB-0001 | [Unfamiliar Sign-In Properties](identity/unfamiliar-sign-in-properties.md) | Identity | Medium | Initial Access, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Lateral Movement, Collection |
