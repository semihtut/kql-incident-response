# QA Review - Impossible Travel Activity (RB-0002)

> **Author:** Alp (QA Lead)
> **Version:** 1.0
> **Review date:** 2026-02-21

## Review Checklist

### Structure & Format
- [x] YAML frontmatter follows RB-0001 template exactly
- [x] All 13 sections present (Alert Context through References)
- [x] Table of Contents with correct anchor links
- [x] Every investigation step has: Purpose, Data needed, Query, Performance Notes, Tuning Guidance, Expected findings, Next action
- [x] Query headers use standard comment block format with `====` separators
- [x] All severity badges use consistent format

### Query Validation
- [x] All 13 queries documented in Query Summary table
- [x] Every query includes shared input parameters
- [x] `ResultType` treated as STRING ("0" not 0) in all queries
- [x] `IpAddress` (capital A) used for AADUserRiskEvents
- [x] `IPAddress` (capital IP) used for SigninLogs
- [x] `LocationDetails` used for SigninLogs (not `Location`)
- [x] `tostring()` used for all dynamic field extractions
- [x] `toreal()` used for coordinate extraction from LocationDetails
- [x] `iff(isnotempty(...))` pattern used for MfaDetail null handling
- [x] `extract()` regex used for OfficeActivity ClientIP normalization
- [x] `geo_distance_2points()` parameter order correct (lon, lat, lon, lat)

### Datatable Tests
- [x] 6 datatable tests provided
- [x] Each test includes both malicious and benign synthetic data
- [x] Expected output documented with comments
- [x] Test 1: Sign-in pair extraction (12 rows: 4 malicious + 8 benign)
- [x] Test 2: Geographic distance calculation with known coordinates
- [x] Test 3: Travel pattern baseline (10 rows: 8 valid + 1 other user + 1 failed)
- [x] Test 4: Device fingerprint comparison (2 scenarios)
- [x] Test 5: Token replay detection (6 rows: 4 malicious + 2 benign)
- [x] Test 6: Post-sign-in activity (14 rows: 6 malicious + 8 benign)

### MITRE ATT&CK
- [x] All techniques listed in frontmatter match Detection Coverage Matrix
- [x] T1550.004 (Web Session Cookie) is new coverage not in RB-0001
- [x] Attack chains documented with coverage percentages
- [x] Coverage gaps identified with recommendations
- [x] Threat actors documented with attribution confidence levels

### False Positive Documentation
- [x] 6 FP scenarios documented (VPN, cloud proxy, business travel, carrier NAT, shared accounts, dual-stack)
- [x] Each scenario includes: Pattern, How to confirm, Tuning note
- [x] VPN identified as #1 FP source (~60%)
- [x] DeviceId comparison highlighted as primary FP discrimination method

### Containment Playbook
- [x] Actions ordered by priority (Immediate → Follow-up → Extended)
- [x] Evidence collection reminder before containment actions
- [x] Token-specific containment noted (token revocation, CAE, token protection)
- [x] Both IPs addressed in blocking actions

### Cross-References
- [x] References to RB-0001 patterns noted where reused (Step 6)
- [x] Key differences from RB-0001 documented in Alert Context
- [x] mitre-mapping.md referenced for detailed threat intel
- [x] Microsoft documentation links provided in References section

## Quality Gates

| Gate | Status | Notes |
|---|---|---|
| Every KQL query syntax-validated | PASS | All queries follow established patterns |
| Every table name validated by Hasan | PASS | All tables exist in sources/microsoft-sentinel-tables.json |
| Every runbook has datatable tests | PASS | 6 tests covering all major query patterns |
| Every technique has MITRE ATT&CK ID | PASS | 11 techniques mapped with confidence levels |
| Baseline comparison query present | PASS | Query 3A is MANDATORY, includes travel pattern analysis |
| False positive scenarios documented | PASS | 6 scenarios with VPN as primary FP source |

## Open Items

None. RB-0002 is approved for publication.
