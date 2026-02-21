# Contributing

Thank you for your interest in contributing to the KQL Incident Response Playbooks. This guide covers the standards and process for submitting new runbooks.

## Runbook Template

Every runbook must include these sections in order:

| # | Section | Required |
|---|---------|----------|
| 1 | YAML Metadata | Yes |
| 2 | Overview & Description | Yes |
| 3 | Prerequisites (log sources, licenses) | Yes |
| 4 | Investigation Steps (ordered KQL queries) | Yes |
| 5 | Baseline Comparison Query | Yes |
| 6 | Containment Actions | Yes |
| 7 | Evidence Collection | Yes |
| 8 | Sample Data (datatable tests) | Yes |
| 9 | MITRE ATT&CK Mapping Table | Yes |

## Writing Standards

- Use **active voice** and **imperative mood** in investigation steps (e.g., "Check the sign-in logs" not "The sign-in logs should be checked")
- Every KQL query must have a **purpose statement** explaining what it detects and why
- Include **"What to look for"** guidance after each query with specific thresholds and indicators
- Add **decision points** that tell the analyst what to do based on query results
- All output must be in **English**

## Mandatory Baseline Query

Every runbook **must** include at least one baseline comparison query. This is non-negotiable.

Requirements:

- Compare current activity against a **14-30 day historical baseline** for the same entity
- Use statistical methods: count comparison, standard deviation, percentile ranking
- Scope baseline to the **specific entity** (per-user, not org-wide)
- Account for time-based patterns: weekday vs. weekend, business hours vs. off-hours
- Label the step as: **"Step N: Baseline Comparison - Establish Normal Behavior Pattern"**
- If no historical data exists, flag this as an additional risk indicator

## Synthetic Test Data

Every runbook must include `datatable`-based inline test data. Minimum requirements:

- At least **10 billion-row scale** test scenarios (10B+ record simulation patterns)
- At least **5 million-row scale** realistic sample datasets (5M+ record patterns)
- Test data must exercise both **benign** and **malicious** patterns
- Use RFC 5737 IP ranges (`198.51.100.0/24`, `203.0.113.0/24`) for test IPs
- Use `contoso.com` domain for test users

## Quality Gates

Before submitting a PR, verify:

- [ ] Every KQL query is syntax-validated
- [ ] Every table name exists in `sources/microsoft-sentinel-tables.json`
- [ ] Every runbook has at least one `datatable`-based test
- [ ] Every runbook has MITRE ATT&CK technique IDs
- [ ] Every runbook has a baseline comparison query
- [ ] File names use kebab-case (e.g., `mass-secret-retrieval.md`)
- [ ] All queries use lowercase, no spaces in filenames

## File Naming

- Runbooks: `kebab-case.md` (e.g., `unfamiliar-sign-in-properties.md`)
- Standalone queries: numbered prefix (e.g., `01-detect-mass-access.kql`)
- All lowercase, no spaces

## Workflow

New runbooks follow this agent workflow:

1. **Arina** (IR Architect) defines the investigation flow and decision tree
2. **Hasan** (Platform Architect) validates table names, schemas, and license requirements
3. **Samet** (KQL Engineer) writes and optimizes the queries
4. **Yunus** (Threat Intel Lead) provides MITRE ATT&CK mappings
5. **Alp** (QA Lead) reviews everything before merge

## PR Process

1. Fork the repository and create a feature branch
2. Add your runbook following the template and standards above
3. Run `mkdocs build --strict` locally to verify no broken links
4. Submit a PR with a clear description of the alert being covered
5. The QA Lead will review against all quality gates before approval

## Scope

We accept runbooks for:

- **Tier 1**: Common identity-based alerts (unfamiliar sign-in, MFA fatigue, suspicious browser, etc.)
- **Tier 2**: Privilege escalation, lateral movement, data exfiltration
- **Tier 3**: Cloud-native attacks (Key Vault abuse, storage exposure, subscription hijacking)

Supported platforms: Microsoft Sentinel, Defender XDR suite, Entra ID, Office 365, Azure Infrastructure, Okta (via Sentinel connector).
