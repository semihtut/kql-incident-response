# KQL Incident Response Playbooks - Project Orchestrator

## Project Overview
This is an open-source project that provides structured, KQL-based incident response runbooks for the full Microsoft cloud security ecosystem (Sentinel, Defender suite, Entra ID, Office 365, Azure Infrastructure). Each runbook is a complete investigation guide with step-by-step queries, explanations, MITRE ATT&CK mappings, and synthetic test data.

## Language Policy
- All project output (runbooks, code, documentation, comments) must be in English
- Coordinator (project owner) communicates in Turkish and English

## Team Structure
This project uses a multi-agent team. Each agent has a dedicated skill file in .claude/agents/:
1. **Leo** - Project Coordinator & Orchestrator (project owner, manages all agents)
2. **Hasan** - Platform Architect (.claude/agents/platform-architect.md) - Microsoft ecosystem expert, table schemas, log sources, licensing
3. **Samet** - KQL Engineer (.claude/agents/kql-engineer.md) - Query development, optimization, testing
4. **Arina** - IR Architect (.claude/agents/ir-architect.md) - Investigation flow design, decision trees, runbook logic
5. **Yunus** - Threat Intel Lead (.claude/agents/threat-intel-lead.md) - MITRE ATT&CK mapping, TTP analysis, detection coverage
6. **Alp** - QA Lead (.claude/agents/qa-lead.md) - Documentation quality, synthetic data, validation, CI/CD
7. **Emre** - Web Architect (.claude/agents/web-architect.md) - MkDocs customization, frontend development, interactive components
8. **Defne** - UX/Content Designer (.claude/agents/ux-designer.md) - Visual identity, page layouts, user experience, accessibility

### Communication Protocol
- Leo (Coordinator) communicates with all agents and makes final decisions
- Agents refer to each other by name in their outputs (e.g., "Hasan confirmed table schema", "Waiting for Arina's investigation flow before writing queries")
- When an agent needs input from another agent, they explicitly state: "I need [Name] to provide [what] before I can proceed"
- Workflow order for new runbooks: Arina (flow) → Hasan (tables) → Samet (queries) → Yunus (MITRE) → Alp (review)

### Website Enhancement Workflow
For website improvements: Defne (design spec) → Emre (implementation) → Alp (review)
Defne defines what it should look like and why. Emre builds it. Alp validates quality.

## Agent Coordination Rules
- Hasan (Platform Architect) must validate table names and schemas BEFORE Samet (KQL Engineer) writes queries
- Arina (IR Architect) defines the investigation flow BEFORE queries are written
- Yunus (Threat Intel Lead) provides MITRE mappings BEFORE runbook is finalized
- Alp (QA Lead) reviews EVERYTHING before it merges - queries, docs, and test data
- No runbook is complete without: queries + explanations + MITRE mapping + sample data + test

## Scope
- Cloud Platform: Microsoft Azure (full ecosystem)
- Log Sources: Entra ID, Identity Protection, Defender for Endpoint, Defender for Office 365, Defender for Cloud Apps, Defender for Identity, Defender for Cloud, OfficeActivity, AzureActivity, AzureDiagnostics, PIM, Okta (via Sentinel connector)
- Every runbook must map to MITRE ATT&CK tactics and techniques
- Runbooks are prioritized in tiers:
  - Tier 1: Most common identity-based alerts (unfamiliar sign-in, MFA fatigue, suspicious browser, etc.)
  - Tier 2: Privilege escalation, lateral movement, data exfiltration
  - Tier 3: Cloud-native attacks (Key Vault abuse, storage exposure, subscription hijacking)

## Runbook Standard Format
Every runbook must follow this structure:
1. **Metadata** - Name, severity, MITRE ATT&CK mapping, description, log sources required, license requirements
2. **Investigation Steps** - Ordered queries with: KQL query, purpose, what to look for, decision points
3. **Containment Actions** - Recommended response actions
4. **Evidence Collection** - What to preserve for forensics
5. **Sample Data** - Synthetic test data with datatable-based inline tests

### Alert Name Recognition & Auto-Generation
When a user provides an alert name (e.g., "Unfamiliar sign-in properties", "Mass secret retrieval", "MFA fatigue"), the system must:
1. Immediately recognize the alert - identify which Microsoft product generates it, which log tables are involved, and which MITRE ATT&CK techniques it maps to
2. Auto-generate a complete runbook following the standard format without needing additional input
3. If the alert name is ambiguous or could match multiple products (e.g., "Impossible travel" exists in both Identity Protection and Defender for Cloud Apps), ask the user to clarify the source
4. If the alert name is not recognized, search for the closest matching alert and suggest it to the user
5. Support common variations: users might type "unfamiliar sign-in", "Unfamiliar Sign-In Properties", "unfamiliar signin" - all should resolve to the same runbook

The IR Architect must maintain an internal mapping of all known Microsoft security alert names to their products, log sources, and investigation requirements. The Platform Architect must validate that the correct tables are referenced. The Threat Intel Lead must provide immediate MITRE mapping.

## Auto-Generation System (mkdocs-macros-plugin)
This project uses `mkdocs-macros-plugin` with a Python hook (`main.py`) to auto-generate index pages, gallery cards, and homepage stats from runbook frontmatter. This eliminates manual updates when adding new runbooks.

### How It Works
- `main.py` at project root defines `define_env()` which scans `docs/runbooks/*/` directories at build time
- It parses YAML frontmatter from each runbook `.md` file and registers Jinja2 template variables
- Pages use `{{ variable }}` and `{% for %}` syntax instead of hardcoded content

### Adding a New Runbook (Only 2 Steps)
1. Create the `.md` file in the correct category directory (e.g., `docs/runbooks/identity/new-alert.md`) with proper frontmatter
2. Add the page to `mkdocs.yml` nav section

Everything else is automatic:
- **Homepage** (`docs/index.md`): Stats (runbook count, MITRE techniques, log tables, tactics) and "Latest Runbooks" cards update automatically
- **Runbook Overview** (`docs/runbooks/index.md`): Categories table counts and Runbook Index table update automatically
- **Gallery** (`docs/runbooks/gallery.md`): Cards and filter buttons (severity/tactic) update automatically
- **Category Index** (e.g., `docs/runbooks/identity/index.md`): Published Runbooks table updates automatically

### Planned Runbooks
Runbooks not yet written are defined in `docs/_data/planned_runbooks.yml`. When a `.md` file with the same `id` is created, the planned entry is automatically superseded.

### Key Files
- `main.py` - mkdocs-macros hook with `define_env()`, `scan_runbooks()`, `load_planned_runbooks()`
- `docs/_data/planned_runbooks.yml` - Planned runbook definitions
- Template variables available in Jinja2: `runbooks`, `planned_runbooks`, `all_runbooks`, `categories`, `stats`, `all_tactics`, `all_severities`, `tactic_short`

### Important: Jinja2 in Markdown
- Pages that use auto-generation contain `{{ }}` and `{% %}` Jinja2 syntax
- KQL queries in runbook content use `}}` (from JSON in `dynamic()`) but NOT `{{`, so there is no conflict
- Do NOT add `{{ }}` patterns outside of code blocks in runbook content pages

## File Naming Convention
- Runbooks: kebab-case (e.g., mass-secret-retrieval.md)
- Queries: numbered prefix (e.g., 01-detect-mass-access.kql)
- All lowercase, no spaces

## Quality Gates
- Every KQL query must be syntax-validated
- Every table name must exist in /sources/ mapping files
- Every runbook must have at least one datatable-based test
- Every runbook must have MITRE ATT&CK technique IDs

### Mandatory Baseline Analysis
Every runbook MUST include at least one baseline comparison query. This is non-negotiable. The investigation cannot determine if activity is truly anomalous without understanding what "normal" looks like for the affected entity.

Baseline query requirements:
- Compare current activity against a 14-30 day historical baseline for the same entity (user, service principal, IP, device)
- Use statistical methods: count comparison, standard deviation, percentile ranking
- Always scope baseline to the specific entity, not global averages (per-user baseline, not org-wide)
- Account for time-based patterns: weekday vs weekend, business hours vs off-hours
- The baseline query should clearly show: "This entity normally does X, but today did Y"
- If no historical data exists for the entity (new account, new device), flag this as an additional risk indicator

Every runbook must have this step labeled as: "Step N: Baseline Comparison - Establish Normal Behavior Pattern"
