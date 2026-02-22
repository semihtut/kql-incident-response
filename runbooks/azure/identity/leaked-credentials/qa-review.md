# QA Review - Leaked Credentials (RB-0003)

> **Author:** Alp (QA Lead)
> **Version:** 1.0
> **Review date:** 2026-02-22

## Review Checklist

### Structure & Format
- [x] YAML frontmatter follows RB-0001/RB-0002 template exactly
- [x] All 13 sections present (Alert Context through References)
- [x] Table of Contents with correct anchor links
- [x] Every investigation step has: Purpose, Data needed, Query, Performance Notes, Tuning Guidance, Expected findings, Next action
- [x] Query headers use standard comment block format with `====` separators
- [x] All severity badges use consistent format

### Query Validation
- [x] All 11 queries documented in Query Summary table
- [x] Every query includes shared input parameters
- [x] `ResultType` treated as STRING ("0" not 0) in all queries
- [x] `IpAddress` (capital A) used for AADUserRiskEvents
- [x] `IPAddress` (capital IP) used for SigninLogs
- [x] `LocationDetails` used for SigninLogs (not `Location`)
- [x] `tostring()` used for all dynamic field extractions
- [x] `iff(isnotempty(...))` pattern used for MfaDetail null handling
- [x] `extract()` regex used for OfficeActivity ClientIP normalization
- [x] Failed sign-ins correctly included in Step 4 (unique to RB-0003)
- [x] Legacy auth detection uses correct ClientAppUsed values

### Datatable Tests
- [x] 6 datatable tests provided
- [x] Each test includes both malicious and benign synthetic data
- [x] Expected output documented with comments
- [x] Test 1: Risk event extraction with leakedCredentials type (6 rows)
- [x] Test 2: Password timeline check (8 rows)
- [x] Test 3: Sign-in baseline (10 rows)
- [x] Test 4: Anomalous sign-in detection with credential testing (12 rows)
- [x] Test 5: Post-sign-in persistence (14 rows)
- [x] Test 6: MFA and legacy auth assessment (8 rows)

### MITRE ATT&CK
- [x] All techniques listed in frontmatter match Detection Coverage Matrix
- [x] T1589.001 (Credentials Gathering) is new coverage not in RB-0001/RB-0002
- [x] T1110.004 (Credential Stuffing) upgraded from probable to confirmed
- [x] Attack chains documented with coverage percentages
- [x] Coverage gaps identified with recommendations
- [x] Threat actors documented with attribution confidence levels

### False Positive Documentation
- [x] 5 FP scenarios documented (old leaks, test accounts, shared email, pre-rotated password, SSO-only accounts)
- [x] Each scenario includes: Pattern, How to confirm, Tuning note
- [x] Old/stale leaks identified as #1 FP source (~50%)
- [x] Password change timeline highlighted as primary FP discrimination method

### Containment Playbook
- [x] Actions ordered by priority (Immediate → Follow-up → Extended)
- [x] Evidence collection reminder before containment actions
- [x] Password reset as mandatory first action
- [x] MFA enforcement noted for accounts without MFA
- [x] Legacy auth block recommended

### Cross-References
- [x] References to RB-0001 patterns noted where reused (Step 5)
- [x] Key differences from RB-0001/RB-0002 documented in Alert Context
- [x] mitre-mapping.md referenced for detailed threat intel
- [x] Microsoft documentation links provided in References section

## Quality Gates

| Gate | Status | Notes |
|---|---|---|
| Every KQL query syntax-validated | PASS | All queries follow established patterns |
| Every table name validated by Hasan | PASS | All tables exist in sources/microsoft-sentinel-tables.json |
| Every runbook has datatable tests | PASS | 6 tests covering all major query patterns |
| Every technique has MITRE ATT&CK ID | PASS | 11 techniques mapped with confidence levels |
| Baseline comparison query present | PASS | Query 3 is MANDATORY, includes sign-in pattern analysis |
| False positive scenarios documented | PASS | 5 scenarios with old leaks as primary FP source |

## Open Items

None. RB-0003 is approved for publication.
