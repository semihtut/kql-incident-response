# KQL Incident Response Playbooks

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Runbooks](https://img.shields.io/badge/runbooks-1-green.svg)](#coverage)
[![MITRE Techniques](https://img.shields.io/badge/MITRE_techniques-15-orange.svg)](mitre-coverage.md)
[![Log Tables](https://img.shields.io/badge/log_tables-43-purple.svg)](log-sources.md)

Structured, KQL-based incident response runbooks for the full Microsoft cloud security ecosystem. Each runbook is a complete investigation guide with step-by-step queries, explanations, MITRE ATT&CK mappings, and synthetic test data.

---

## Key Features

- **Step-by-step KQL queries** with explanations of what to look for and why
- **MITRE ATT&CK mapping** for every runbook with tactic and technique IDs
- **Baseline comparison queries** to distinguish anomalous activity from normal behavior
- **Synthetic test data** using `datatable` for validation without production access
- **Decision trees** that guide analysts through investigation branching logic
- **Containment actions** with specific remediation commands and procedures
- **Evidence collection** checklists for forensic preservation

## Quick Start

**1. Find your alert**

Browse the [Runbooks](runbooks/index.md) section or search for your alert name.

**2. Check prerequisites**

Each runbook lists required log sources, license tiers, and RBAC roles. See [Getting Started](getting-started.md) for details.

**3. Run the queries**

Copy KQL queries directly into Microsoft Sentinel Log Analytics and follow the investigation flow.

---

## Coverage {#coverage}

| Category | Runbooks | Status |
|----------|----------|--------|
| [Identity](runbooks/identity/index.md) | 1 completed | Active |
| [Endpoint](runbooks/endpoint/index.md) | Planned | Tier 2 |
| [Email](runbooks/email/index.md) | Planned | Tier 2 |
| [Cloud Apps](runbooks/cloud-apps/index.md) | Planned | Tier 2 |
| [Azure Infrastructure](runbooks/azure-infrastructure/index.md) | Planned | Tier 3 |
| [Okta](runbooks/okta/index.md) | Planned | Tier 2 |

See [Log Sources](log-sources.md) for the full list of 43 supported Sentinel tables across 11 categories.

---

## Team

This project is built by a multi-disciplinary security team:

- **Leo** - Project Coordinator & Orchestrator
- **Hasan** - Platform Architect (Microsoft ecosystem, table schemas, licensing)
- **Samet** - KQL Engineer (query development, optimization, testing)
- **Arina** - IR Architect (investigation flows, decision trees, runbook logic)
- **Yunus** - Threat Intel Lead (MITRE ATT&CK mapping, TTP analysis)
- **Alp** - QA Lead (documentation quality, synthetic data, validation)
