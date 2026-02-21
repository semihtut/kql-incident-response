# QA Review: Unfamiliar Sign-In Properties Runbook

**Reviewed by:** Alp (Documentation & QA Lead)
**Review Date:** 2026-02-21
**Re-Review Date:** 2026-02-21
**Review Scope:** Assembled README.md (final published runbook)
**Approval Status:** APPROVED

---

## Re-Review Summary

This is the final QA re-review of the assembled runbook (README.md, 3,117 lines). All 6 required changes (S1-S6) from the initial review have been addressed. The runbook passes all 4 levels of validation and is approved for publication as RB-0001 v1.0.

---

## 1. Compliance Checklist (Re-Assessment)

Evaluated against CLAUDE.md Runbook Standard Format and my Document Structure Standards.

| # | Required Section | Status | Location | Notes |
|---|---|---|---|---|
| 1 | YAML Frontmatter (Metadata) | **PASS** | Lines 1-126 | Complete schema with 7 tactics, 11 techniques, 3 threat actors, 11 log sources. All fields present per my schema definition. |
| 2 | Overview (2-3 sentences) | **PASS** | Lines 161-178 | "Alert Context" section. Clear explanation of trigger, significance, FP patterns, and worst-case scenario. |
| 3 | Prerequisites (log sources, licenses, permissions) | **PASS** | Lines 180-205 | Minimum required, recommended, data availability check, and licensing-per-step table. Fully addresses S4. |
| 4 | Investigation Steps (numbered, sequential) | **PASS** | Lines 243-1632 | 7 steps with 18 production queries inline, decision criteria at each step, linear flow. |
| 5 | Containment Actions (ordered by priority) | **PASS** | Lines 1634-1668 | 12 actions in 3 priority tiers (Immediate/Follow-up/Extended). Evidence-before-containment warning. |
| 6 | Evidence Collection Checklist | **PASS** | Lines 1670-1689 | 14 items in checkbox format. Correctly placed before containment reference. |
| 7 | False Positive Guidance | **PASS** | Lines 1716-1750 | 6 documented FP scenarios with pattern/confirmation/tuning structure. |
| 8 | MITRE ATT&CK References | **PASS** | Lines 1752-1845 | 15 techniques, 3 attack chains, 5 coverage gaps. Condensed from full mapping with link to mitre-mapping.md. |
| 9 | Test Queries (datatable) | **PASS** | Lines 1878-3108 | 7 datatable tests, all meeting 10B+5M minimums. |
| 10 | Baseline Comparison Query | **PASS** | Lines 622-806 | 30-day baseline with 6-property comparison. Labeled "Step 3: Baseline Comparison - Establish Normal Behavior Pattern". Meets CLAUDE.md mandatory requirement. |

**Compliance Score: 10/10 PASS** (previously 7/10 PASS, 2 PARTIAL, 1 MISSING)

---

## 2. Required Changes (S1-S6) - Resolution Verification

| # | Original Issue | Status | Evidence |
|---|---|---|---|
| S1 | Create YAML frontmatter | **RESOLVED** | Lines 1-126. Complete frontmatter following my schema. All 11 log sources with product/license/required/alternatives. 11 techniques with confidence levels. 3 threat actors. |
| S2 | Update status lines | **RESOLVED** | README.md is the assembled runbook - no stale status lines present. Working documents (investigation-flow.md, queries.md, mitre-mapping.md) are now internal files. |
| S3 | Remove team coordination artifacts | **RESOLVED** | No "I need Hasan to validate..." or "Samet's notes for..." artifacts in README.md. Working documents retained for internal reference. |
| S4 | Add Prerequisites section | **RESOLVED** | Lines 180-205. Includes minimum required licenses, recommended licenses, data availability checks, and licensing-per-step table. Exceeds my recommendation. |
| S5 | Expand datatable tests to meet minimums | **RESOLVED** | All 7 tests expanded. See Section 3 below for row counts. |
| S6 | Add datatable test for Query 5A | **RESOLVED** | Lines 2636-2837. 18 rows (6 malicious + 12 benign). Covers MFA registration, OAuth consent, API permissions, device registration, role escalation, MFA deletion. |

**All 6 required changes resolved.**

---

## 3. Test Coverage (Re-Assessment)

### Datatable Test Row Counts

| Test | Query | Malicious | Benign | Total | Min Met (5M+10B) | Edge Cases | Verdict |
|---|---|---|---|---|---|---|---|
| Test 1 | Query 1 | 5 | 10 | 15+15 (dual table) | **YES** | null Location ✓, empty UserAgent ✓, out-of-window ✓, spray indicator ✓, multiple risk types ✓ | **PASS** |
| Test 2 | Query 2B | 6 | 12 | 18 | **YES** | MFA deletion ✓, delegated perms ✓, before/after timing ✓, different initiators ✓ | **PASS** |
| Test 3 | Query 3A | 5 | 12+1 excluded | 18 | **YES** | Failed sign-in excluded ✓, mobile device ✓, WFH IP ✓, multiple browsers ✓, AiTM proxy ✓ | **PASS** |
| Test 4 | Query 4A | 7 | 11 | 18 | **YES** | Leaked creds ✓, password spray ✓, impossible travel ✓, outside window ✓, FP traveler ✓ | **PASS** |
| Test 5 | Query 5A | 6 | 12 | 18 | **YES** | Full persistence chain ✓, app-initiated ops ✓, pre-alert window ✓, PIM activation ✓ | **PASS** |
| Test 6 | Query 5B/5C/5D | 8 | 12 | 20 | **YES** | IPv6-mapped IP ✓, port stripping ✓, pre-alert activity ✓, mobile IP ✓ | **PASS** |
| Test 7 | Query 6A | 5 | 13 | 18 | **YES** | Expired indicators ✓, inactive indicators ✓, low confidence ✓, null IP ✓, adjacent IP ✓ | **PASS** |

**Test coverage: 7/7 tests PASS** (previously 0/6 passed minimums)

### Test Quality Assessment

All tests tell a coherent attack story:
- Test 1: Credential theft sign-in from Moscow with bot-like browser, no MFA
- Test 2: Post-compromise account manipulation chain (MFA → OAuth → device → delegation → deletion)
- Test 3: Baseline deviation detection across 5 attack variants vs 12-day benign pattern
- Test 4: Correlated risk event escalation (leaked creds → password spray → unfamiliar + impossible travel + anonymous IP + malicious IP)
- Test 5: Full persistence chain (MFA registration → OAuth consent → API permissions → device → role escalation → MFA deletion)
- Test 6: BEC attack pattern (inbox rule → forwarding → email scraping → file exfil → internal phishing)
- Test 7: Multi-source TI confirmation (5 feeds, 5 threat types, confidence scoring)

---

## 4. Schema Validation (Re-Assessment)

### YAML Frontmatter Validation

| Field | Required | Present | Valid | Notes |
|---|---|---|---|---|
| title | Yes | Yes | Yes | "Unfamiliar Sign-In Properties" |
| id | Yes | Yes | Yes | RB-0001 (correct format) |
| severity | Yes | Yes | Yes | medium |
| status | No | Yes | Yes | reviewed |
| description | No | Yes | Yes | Multi-line, comprehensive |
| mitre_attack.tactics | Yes | Yes | Yes | 7 tactics (TA0001, TA0003-TA0006, TA0008-TA0009) |
| mitre_attack.techniques | Yes | Yes | Yes | 11 techniques with confidence levels |
| threat_actors | Yes | Yes | Yes | 3 actors |
| log_sources | Yes | Yes | Yes | 11 sources with product/license/required/alternatives |
| author | Yes | Yes | Yes | Full team credit |
| created | Yes | Yes | Yes | 2026-02-21 |
| updated | Yes | Yes | Yes | 2026-02-21 |
| version | Yes | Yes | Yes | "1.0" |
| tier | Yes | Yes | Yes | 1 |

**Frontmatter validation: 14/14 fields PASS**

### MITRE ATT&CK ID Format Validation

All 19 technique IDs referenced across the runbook (frontmatter + Section 10 coverage matrix) follow the T####.### or T#### pattern and exist in ATT&CK. **19/19 PASS** (unchanged from initial review).

### Sources Reference Validation

All 11 tables referenced in the queries match the log_sources in the frontmatter. **11/11 PASS** (unchanged from initial review).

---

## 5. Consistency Assessment

### Document Structure

| Element | Standard | README.md | Verdict |
|---|---|---|---|
| H1 heading | One per document | "# Unfamiliar Sign-In Properties - Investigation Runbook" (line 128) | **PASS** |
| H2 for sections | Yes | Sections 1-11 + Appendix + References | **PASS** |
| H3 for subsections | Yes | Steps, sub-sections within investigation | **PASS** |
| H4 for queries | Yes | Query titles within steps | **PASS** |
| Code blocks with language | Always | All production queries use ` ```kql ` | **PASS** |
| Table of Contents | Recommended | Lines 136-157, with anchor links | **PASS** |

### Terminology Consistency (Sampled)

| Term | Usage in README.md | Consistent |
|---|---|---|
| Risk detection / alert | "risk detection" in technical context, "alert" in analyst instructions | **PASS** |
| Analyst | Used consistently throughout investigation steps | **PASS** |
| Target user / affected user | "affected user" in prose, "targetUser" in code | **PASS** |
| Attacker | Used consistently in investigation context | **PASS** |

### Cross-Reference Consistency

| Cross-Reference | Status |
|---|---|
| Table of Contents → Section anchors | **PASS** - All 13 ToC entries resolve to correct sections |
| Query numbers in investigation steps → Query Summary table | **PASS** - All 18 queries listed |
| MITRE technique IDs → Coverage matrix | **PASS** - 15 techniques mapped |
| Step numbers → Sequential flow | **PASS** - Steps 1-7 in order, no backtracking |
| Frontmatter log_sources → Queries | **PASS** - All 11 tables used in queries |

---

## 6. Minor Observations (Non-Blocking)

These are observations only - they do not block publication.

**O1. Attack chain diagrams use bare code fences.**
Lines 1786, 1806, 1821 use ` ``` ` without a language tag. Ideally ` ```text ` for consistency with my markdown standards. This was S9 in the original review (Priority 2 - Recommended). Not blocking.

**O2. Test Query 4A has a simplified RiskSignificance case statement.**
The test (line 2612-2620) maps `anonymizedIPAddress` to "MEDIUM" while the production query (line 967) maps it to "HIGH". This does not affect test validity since the primary purpose is testing row filtering, not label accuracy. For full parity, the test's case logic could mirror production exactly. Not blocking.

**O3. Test 2 expected output comment has minor count discrepancy.**
Line 2337 says "5 other-user rows" but lists 6 IDs (b03, b04, b06, b08, b10, b11). Cosmetic comment issue only. Not blocking.

**O4. Recommended additions from original review (Priority 2-3) not included.**
The following recommendations from my original review were categorized as Priority 2/3 (not required for publication):
- S7: MFA fatigue query (T1621 coverage gap) - suitable for v1.1
- S9: ` ```text ` for attack chain diagrams
- S10: Time-to-investigate estimates per step
- S11: Visual flow diagram

These are valid enhancements for future versions.

---

## 7. Level 1-4 Validation Pipeline Results

### Level 1: Syntax Validation
| Check | Status |
|---|---|
| KQL code blocks specify language (` ```kql `) | **PASS** - All 25 KQL blocks tagged |
| Markdown linting (heading hierarchy, list formatting) | **PASS** |
| YAML frontmatter parseable | **PASS** |
| Code fences balanced | **PASS** - 30 open/close pairs |

### Level 2: Semantic Validation
| Check | Status |
|---|---|
| All 11 table names validated against schema | **PASS** |
| MITRE ATT&CK technique IDs valid (T####.### format) | **PASS** - 19/19 |
| All technique IDs exist in ATT&CK framework | **PASS** |

### Level 3: Consistency Validation
| Check | Status |
|---|---|
| Template compliance (all 9+ required sections present) | **PASS** |
| Terminology consistent throughout | **PASS** |
| Heading hierarchy correct (H1→H2→H3→H4) | **PASS** |
| No orphan links | **PASS** |
| File naming convention | **PASS** (README.md in kebab-case directory) |

### Level 4: Functional Validation
| Check | Status |
|---|---|
| All 7 datatable tests structurally complete | **PASS** |
| All tests meet 10B+5M minimum row requirement | **PASS** |
| Baseline query present with per-entity comparison | **PASS** (Query 3A, 30-day, 6 properties) |
| No query uses undocumented tables/columns | **PASS** |

**All 4 validation levels: PASS**

---

## 8. Approval Status

### APPROVED

**RB-0001 "Unfamiliar Sign-In Properties" v1.0 is approved for publication.**

The assembled README.md is a complete, production-ready runbook that meets all quality standards:

- **Structure:** 13 clearly-organized sections following the project template, with Table of Contents and proper heading hierarchy
- **Content:** 18 production KQL queries across 7 investigation steps, with per-step decision criteria, malicious/benign indicator tables, performance notes, and tuning guidance
- **Testing:** 7 datatable tests with 125+ total synthetic rows (all meeting 10B+5M minimums), covering realistic attack patterns and benign edge cases
- **MITRE Coverage:** 15 techniques mapped across 8 tactics, with 3 documented attack chains and 5 identified coverage gaps
- **Usability:** A Tier 1 analyst can follow this at 3 AM with no prior context. Every step is self-contained. Every decision point has explicit criteria.

### Quality Metrics

| Metric | Value |
|---|---|
| Total lines | 3,117 |
| Production queries | 18 (13 required, 2 recommended, 3 optional) |
| Datatable tests | 7 |
| Total synthetic test rows | 125+ |
| MITRE techniques | 15 (9 full coverage, 6 partial) |
| Attack chains documented | 3 |
| Coverage gaps identified | 5 |
| Log sources covered | 11 |
| FP scenarios documented | 6 |
| Containment actions | 12 (3 priority tiers) |
| Evidence checklist items | 14 |

---

## 9. Recommendation for Next Runbook

The team workflow (Arina → Hasan → Samet → Yunus → Alp → Leo) proved effective. Recommended next runbook:

**Option A (Recommended):** "MFA Fatigue / MFA Bombing" (T1621) - Tier 1, directly complements this runbook, closes Coverage Gap #2
**Option B:** "Impossible Travel" - another high-volume Identity Protection alert, reuses much of the same table/query patterns

---

**Alp's final note to Leo (Coordinator):**
Excellent work assembling this. The transition from 4 separate working documents to a single 3,117-line reader-facing runbook is clean. No team coordination artifacts leaked through. All 6 required changes are fully resolved. The test expansion work (S5/S6) is particularly strong - the attack chain in Test 5 (MFA → OAuth → device → role → MFA deletion) is the most realistic synthetic persistence chain I have seen in a runbook test. Ship it.
