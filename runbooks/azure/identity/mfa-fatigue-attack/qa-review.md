# QA Review - MFA Fatigue Attack (RB-0005)

> **Author:** Alp (QA Lead)
> **Version:** 1.0
> **Review date:** 2026-02-22

## Review Checklist

### Structure & Format
- [x] YAML frontmatter follows RB-0001/RB-0002/RB-0003/RB-0004 template exactly
- [x] All 13 sections present (Alert Context through References)
- [x] Table of Contents with correct anchor links
- [x] Every investigation step has: Purpose, Data needed, Query, Performance Notes, Tuning Guidance, Expected findings, Next action
- [x] Query headers use standard comment block format with `====` separators
- [x] All severity badges use consistent format

### Query Validation
- [x] All 10 queries documented in Query Summary table
- [x] Every query includes shared input parameters
- [x] `ResultType` treated as STRING ("500121", "50074", "0" -- not integers) in all queries
- [x] `MfaDetail` dynamic field handled with `tostring()` and `iff(isnotempty(...))` null-safe pattern
- [x] `AuthenticationDetails` parsed via `mv-expand` for multi-step auth flow analysis
- [x] `bin()` used for temporal bucketing in MFA denial timing analysis (5-minute windows)
- [x] `IPAddress` (capital IP) used consistently for SigninLogs throughout all queries
- [x] `LocationDetails` used for SigninLogs (not `Location`)
- [x] `tostring()` used for all dynamic field extractions
- [x] Primary table is SigninLogs (not AADUserRiskEvents) -- validated by Hasan as correct for MFA prompt telemetry

### Datatable Tests
- [x] 5 datatable tests provided
- [x] Each test includes both malicious and benign synthetic data
- [x] Expected output documented with comments
- [x] Test 1: MFA fraud risk event extraction with denial patterns (6 rows)
- [x] Test 2: MFA denial-then-approval sequence detection (8 rows)
- [x] Test 3: 30-day MFA baseline comparison per user (10 rows)
- [x] Test 4: Post-approval session and directory change activity (12 rows)
- [x] Test 5: Org-wide MFA denial pattern analysis (8 rows)

### MITRE ATT&CK
- [x] All techniques listed in frontmatter match Detection Coverage Matrix
- [x] T1621 (Multi-Factor Authentication Request Generation) is new coverage not in RB-0001/RB-0002/RB-0003/RB-0004
- [x] T1621 provides Credential Access tactic coverage for MFA-specific attacks (first time)
- [x] Attack chains documented with coverage percentages
- [x] Coverage gaps identified with recommendations
- [x] Threat actors documented with attribution confidence levels

### False Positive Documentation
- [x] 4 FP scenarios documented (phone issues, enrollment failures, poor cell coverage, accidental deny-then-retry)
- [x] Each scenario includes: Pattern, How to confirm, Tuning note
- [x] Estimated false positive rate ~20-30% (lower than RB-0004 anonymous IP)
- [x] Phone/device issues identified as #1 FP source -- user phone rebooting or app crashing can mimic rapid denials

### Containment Playbook
- [x] Actions ordered by priority (Immediate -> Follow-up -> Extended)
- [x] Evidence collection reminder before containment actions
- [x] Block sign-in immediately as first action even before investigation completes (unique to RB-0005 -- MFA bombing is active attack in progress)
- [x] Session revocation second
- [x] Credential reset third, followed by MFA method review

### Cross-References
- [x] References to RB-0001 patterns noted where reused (baseline comparison methodology)
- [x] Key differences from RB-0001/RB-0002/RB-0003/RB-0004 documented
- [x] Unique aspects: SigninLogs as primary table (not AADUserRiskEvents), ResultType-based detection logic, temporal clustering analysis for MFA prompt storms
- [x] mitre-mapping.md referenced
- [x] Microsoft documentation links provided

## Quality Gates

| Gate | Status | Notes |
|---|---|---|
| Every KQL query syntax-validated | PASS | All 10 queries follow established patterns; ResultType string comparisons verified |
| Every table name validated by Hasan | PASS | SigninLogs confirmed as primary table for MFA prompt telemetry |
| Every runbook has datatable tests | PASS | 5 tests covering MFA denial patterns, approval sequences, and baseline comparison |
| Every technique has MITRE ATT&CK ID | PASS | T1621 is new coverage addition -- first MFA-specific technique in the project |
| Baseline comparison query present | PASS | Query 4 is MANDATORY 30-day baseline; compares per-user MFA denial frequency against historical norm |
| False positive scenarios documented | PASS | 4 scenarios with phone/device issues as primary FP source (~20-30% rate) |

## Open Items

None. RB-0005 is approved for publication.
