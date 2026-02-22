"""
mkdocs-macros-plugin hook for auto-generating runbook indexes and gallery cards.

Scans docs/runbooks/*/*.md for YAML frontmatter and registers template variables
so that index pages, gallery cards, and homepage stats are generated automatically.
"""

import yaml
from pathlib import Path

DOCS_DIR = Path("docs")
RUNBOOKS_DIR = DOCS_DIR / "runbooks"

CATEGORY_MAP = {
    "identity": "Identity",
    "endpoint": "Endpoint",
    "email": "Email",
    "cloud-apps": "Cloud Apps",
    "azure-infrastructure": "Azure Infrastructure",
    "okta": "Okta",
}

CATEGORY_DESCRIPTIONS = {
    "identity": "Entra ID, Identity Protection, Conditional Access",
    "endpoint": "Defender for Endpoint, device-level threats",
    "email": "Defender for Office 365, phishing, BEC",
    "cloud-apps": "Defender for Cloud Apps, SaaS threats",
    "azure-infrastructure": "Azure control/data plane, Key Vault, Storage",
    "okta": "Okta IdP via Sentinel connector",
}

TACTIC_SLUG_MAP = {
    "Initial Access": "initial-access",
    "Persistence": "persistence",
    "Privilege Escalation": "priv-esc",
    "Defense Evasion": "defense-evasion",
    "Credential Access": "cred-access",
    "Lateral Movement": "lateral-movement",
    "Collection": "collection",
    "Reconnaissance": "recon",
    "Exfiltration": "exfiltration",
    "Command and Control": "c2",
    "Impact": "impact",
    "Execution": "execution",
    "Discovery": "discovery",
    "Resource Development": "resource-dev",
}

TACTIC_SHORT_MAP = {
    "initial-access": "Initial Access",
    "persistence": "Persistence",
    "priv-esc": "Priv Esc",
    "defense-evasion": "Def Evasion",
    "cred-access": "Cred Access",
    "lateral-movement": "Lateral Mov",
    "collection": "Collection",
    "recon": "Recon",
    "exfiltration": "Exfiltration",
    "c2": "C2",
    "impact": "Impact",
    "execution": "Execution",
    "discovery": "Discovery",
    "resource-dev": "Resource Dev",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def extract_frontmatter(path):
    """Parse YAML frontmatter from a markdown file."""
    content = path.read_text(encoding="utf-8")
    if not content.startswith("---"):
        return None
    parts = content.split("---", 2)
    if len(parts) < 3:
        return None
    try:
        return yaml.safe_load(parts[1])
    except yaml.YAMLError:
        return None


def scan_runbooks():
    """Scan docs/runbooks/*/ for .md files with valid frontmatter."""
    runbooks = []
    for category_dir in sorted(RUNBOOKS_DIR.iterdir()):
        if not category_dir.is_dir():
            continue
        category_slug = category_dir.name
        if category_slug not in CATEGORY_MAP:
            continue
        for md_file in sorted(category_dir.glob("*.md")):
            if md_file.name == "index.md":
                continue
            meta = extract_frontmatter(md_file)
            if not meta or "id" not in meta:
                continue

            meta["category_slug"] = category_slug
            meta["category_name"] = CATEGORY_MAP[category_slug]
            meta["file_stem"] = md_file.stem

            # Compute tactic slugs for data-attributes and CSS classes
            tactic_slugs = []
            for tactic in meta.get("mitre_attack", {}).get("tactics", []):
                slug = TACTIC_SLUG_MAP.get(tactic.get("tactic_name", ""), "")
                if slug:
                    tactic_slugs.append(slug)
            meta["tactic_slugs"] = tactic_slugs

            # Tactic names for table display
            meta["tactic_names"] = [
                t.get("tactic_name", "")
                for t in meta.get("mitre_attack", {}).get("tactics", [])
            ]

            # Display status
            if meta.get("status") == "reviewed":
                meta["display_status"] = "Complete"
                meta["status_class"] = "status-complete"
            else:
                meta["display_status"] = meta.get("status", "draft").title()
                meta["status_class"] = f"status-{meta.get('status', 'draft')}"

            # Required log source table names
            meta["key_log_sources"] = [
                ls["table"]
                for ls in meta.get("log_sources", [])
                if ls.get("required")
            ]

            runbooks.append(meta)

    runbooks.sort(key=lambda r: r["id"])
    return runbooks


def load_planned_runbooks(published_ids):
    """Load planned runbooks from YAML data file, skipping already-published IDs."""
    data_file = DOCS_DIR / "_data" / "planned_runbooks.yml"
    if not data_file.exists():
        return []
    try:
        with open(data_file, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError:
        return []

    planned = []
    for entry in data or []:
        if entry.get("id") in published_ids:
            continue
        entry["status"] = "planned"
        entry["display_status"] = "Planned"
        entry["status_class"] = "status-planned"
        entry["category_name"] = CATEGORY_MAP.get(
            entry.get("category", ""), entry.get("category", "")
        )
        tactic_slugs = []
        for tactic_name in entry.get("tactics", []):
            slug = TACTIC_SLUG_MAP.get(tactic_name, "")
            if slug:
                tactic_slugs.append(slug)
        entry["tactic_slugs"] = tactic_slugs
        planned.append(entry)
    return planned


def compute_categories(runbooks, planned=None):
    """Group published runbooks by category with counts."""
    cats = {}
    for rb in runbooks:
        slug = rb["category_slug"]
        if slug not in cats:
            cats[slug] = {
                "slug": slug,
                "name": CATEGORY_MAP[slug],
                "count": 0,
                "planned_count": 0,
                "runbooks": [],
            }
        cats[slug]["count"] += 1
        cats[slug]["runbooks"].append(rb)

    # Add empty categories so templates can iterate all
    for slug, name in CATEGORY_MAP.items():
        if slug not in cats:
            cats[slug] = {
                "slug": slug,
                "name": name,
                "count": 0,
                "planned_count": 0,
                "runbooks": [],
            }

    # Count planned (not-yet-published) runbooks per category
    for entry in planned or []:
        slug = entry.get("category", "")
        if slug in cats:
            cats[slug]["planned_count"] += 1

    # Compute total and percentage for each category
    for slug, cat in cats.items():
        cat["total"] = cat["count"] + cat["planned_count"]
        cat["pct"] = round(cat["count"] / cat["total"] * 100) if cat["total"] > 0 else 0

    return cats


def render_data_check_timeline(checks):
    """Generate the Data Availability Check timeline HTML from a list of check dicts."""
    if not checks:
        return ""

    lines = [
        '<div class="data-check-timeline" markdown="0">',
        '  <div class="data-check-header">',
        '    <span class="data-check-title">Data Availability Check</span>',
        '    <span class="data-check-subtitle">Before starting the investigation, verify these tables contain data</span>',
        "  </div>",
        '  <div class="data-check-steps">',
    ]

    for i, check in enumerate(checks):
        label = check.get("label", "")
        is_primary = label == "primary"
        is_optional = label == "optional"
        step_class = "data-check-step primary" if is_primary else "data-check-step"

        if i > 0:
            lines.append('    <div class="data-check-connector"></div>')

        lines.append(f'    <div class="{step_class}">')
        lines.append(f'      <div class="data-check-num">{i + 1}</div>')
        lines.append('      <div class="data-check-body">')
        lines.append(f'        <code>{check["query"]}</code>')

        if is_primary:
            lines.append(
                '        <span class="data-check-badge primary">PRIMARY</span>'
            )
        elif is_optional:
            lines.append(
                '        <span class="data-check-badge optional">OPTIONAL</span>'
            )

        desc = check.get("description", "")
        lines.append(f"        <p>{desc}</p>")
        lines.append("      </div>")
        lines.append("    </div>")

    lines.append("  </div>")
    lines.append("</div>")
    return "\n".join(lines)


CATEGORY_ICONS = {
    "identity": "&#128274;",       # lock
    "endpoint": "&#128187;",       # laptop
    "email": "&#128231;",          # envelope
    "cloud-apps": "&#9729;",       # cloud
    "azure-infrastructure": "&#9881;",  # gear
    "okta": "&#128273;",           # key
}


def render_coverage_cards(categories):
    """Generate the Coverage Cards HTML grid from category data."""
    order = ["identity", "endpoint", "email", "cloud-apps", "azure-infrastructure", "okta"]
    lines = ['<div class="coverage-cards" markdown="0">']

    for slug in order:
        cat = categories.get(slug)
        if not cat:
            continue
        count = cat["count"]
        total = cat["total"]
        pct = cat.get("pct", 0)
        icon = CATEGORY_ICONS.get(slug, "")
        active_class = " active" if count > 0 else ""

        lines.append(f'  <a class="coverage-card{active_class}" href="runbooks/{slug}/">')
        lines.append(f'    <span class="coverage-card-icon">{icon}</span>')
        lines.append(f'    <span class="coverage-card-name">{cat["name"]}</span>')

        if count > 0:
            lines.append(f'    <span class="coverage-card-stat">{count} runbook{"s" if count != 1 else ""}</span>')
            lines.append('    <div class="coverage-card-bar">')
            lines.append(f'      <div class="coverage-card-fill" style="width: {pct}%"></div>')
            lines.append("    </div>")
            if total > count:
                lines.append(f'    <span class="coverage-card-detail">{count} of {total} planned</span>')
        else:
            lines.append('    <span class="coverage-card-stat coming-soon">Coming Soon</span>')

        lines.append("  </a>")

    lines.append("</div>")
    return "\n".join(lines)


def define_env(env):
    """Called by mkdocs-macros-plugin at build time."""
    runbooks = scan_runbooks()
    published_ids = {rb["id"] for rb in runbooks}
    planned = load_planned_runbooks(published_ids)

    all_runbooks = sorted(runbooks + planned, key=lambda r: r["id"])
    categories = compute_categories(runbooks, planned)

    # Distinct tactics across all runbooks (published + planned)
    all_tactics = []
    seen_tactics = set()
    for rb in all_runbooks:
        for slug in rb.get("tactic_slugs", []):
            if slug not in seen_tactics:
                seen_tactics.add(slug)
                all_tactics.append(slug)

    # Distinct severities in display order
    all_severities = sorted(
        {rb.get("severity", "") for rb in all_runbooks if rb.get("severity")},
        key=lambda s: SEVERITY_ORDER.get(s, 99),
    )

    # Stats for homepage
    unique_techniques = set()
    unique_tactics = set()
    for rb in runbooks:
        for t in rb.get("mitre_attack", {}).get("techniques", []):
            unique_techniques.add(t.get("technique_id", ""))
        for t in rb.get("mitre_attack", {}).get("tactics", []):
            unique_tactics.add(t.get("tactic_id", ""))

    # Count total platform-supported log tables from log-sources.md
    log_sources_file = DOCS_DIR / "log-sources.md"
    table_count = 0
    if log_sources_file.exists():
        for line in log_sources_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("| [") and "learn.microsoft.com" in line:
                table_count += 1
    if table_count == 0:
        table_count = 43  # fallback

    env.variables["runbooks"] = runbooks
    env.variables["planned_runbooks"] = planned
    env.variables["all_runbooks"] = all_runbooks
    env.variables["categories"] = categories
    env.variables["category_descriptions"] = CATEGORY_DESCRIPTIONS
    env.variables["all_tactics"] = all_tactics
    env.variables["all_severities"] = all_severities
    env.variables["tactic_short"] = TACTIC_SHORT_MAP
    env.variables["tactic_slug_map"] = TACTIC_SLUG_MAP
    env.variables["stats"] = {
        "runbook_count": len(runbooks),
        "technique_count": len(unique_techniques),
        "tactic_count": len(unique_tactics),
        "table_count": table_count,
    }

    # Register macros
    @env.macro
    def data_check_timeline(checks=None):
        """Render Data Availability Check timeline from frontmatter data_checks."""
        return render_data_check_timeline(checks)

    @env.macro
    def coverage_cards():
        """Render Coverage Cards grid for the homepage."""
        return render_coverage_cards(categories)
