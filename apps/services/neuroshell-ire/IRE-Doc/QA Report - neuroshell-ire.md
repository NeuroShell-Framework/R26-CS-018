# QA Report — neuroshell-ire (Component 01 / R26-CS-018)

**Subject:** NeuroShell IRE — Intent Recognition Engine (NLU gateway)
**Scope:** Automated test suite, code coverage, static analysis, empirical evaluation, known gaps, and recommendations.
**Report date:** 2026-08-30
**Commit under test:** `ebb50d4` (`feat: C3/C4 service restructure + multi-vuln chain demo + C1 cache wiring`)
**Environment:** Windows, Python 3.9.13 (venv), pytest 8.3.2, coverage 7.10.7, ruff 0.16.5
**Test runner:** `.venv\Scripts\python.exe -m pytest` (from service root `apps\services\neuroshell-ire`)

---

## 1. Executive Summary

| Dimension | Result |
|---|---|
| **Test suite** | **506 tests — 506 passed, 0 failed, 0 errors** (434 unit + 72 integration) |
| **Test duration** | 49.7 s (plain) / 55.1 s (with coverage) |
| **Code coverage** | **76%** statement coverage across `src/` (2421 stmts, 582 miss) |
| **High-coverage core** | 8 modules at 100%, core validation + middleware mostly 89–99% |
| **Static analysis** | 593 ruff findings — 100% style/modernisation; no correctness-level (E9) errors, 0 fatal |
| **Latest additions** | 23 new integration tests combining AdversarialDetector + AliasResolver + AuditLogger + full pipeline |

**Verdict:** The suite is green, deterministic (no live-LLM dependency in unit/integration paths), and the safety-critical core (adversarial detection, RBAC, validation stack, scope enforcement) is well covered. The two weakest quality areas are (a) code coverage of orchestration/integration-client modules and (b) documented evaluation-methodology gaps (single-run experiments, confidence calibration, threshold sensitivity).

---

## 2. Test Execution Results

### 2.1 Full Suite

```
============================ 506 passed in 49.66s =============================
```

### 2.2 Per-File Inventory (collected 2026-08-30)

| Test file | Tests | Coverage target |
|---|---|---|
| `tests/integration/test_api.py` | 12 | FastAPI `/parse`, `/metrics`, auth |
| `tests/integration/test_api_v2.py` | 34 | V2 schema, middleware wiring, cache/session/RBAC endpoints |
| `tests/integration/test_audit_escalation_api.py` | 3 | Escalation queue + admin resolve API |
| `tests/integration/test_integration_adversarial_alias.py` | 8 | AdversarialDetector + AliasResolver chain |
| `tests/integration/test_integration_adversarial_alias_audit.py` | 6 | Adversarial + Alias + AuditLogger (privacy, escalation) |
| `tests/integration/test_integration_pipeline_full_stack.py` | 9 | Full 7-stage pipeline with mocked LLM |
| `tests/unit/test_adversarial_detector.py` | 42 | 3-layer threat scoring (lexical/structural/scoring) |
| `tests/unit/test_alias_resolver.py` | 20 | Jargon→CVE expansion |
| `tests/unit/test_audit_logger.py` | 5 | SQLite audit, hashing, escalation roundtrip |
| `tests/unit/test_cve_grounding.py` | 5 | Offline CVE grounding |
| `tests/unit/test_enforcement_policy.py` | 4 | Policy engine, scope modes |
| `tests/unit/test_feature_flags.py` | 29 | YAML flags + tuning, reload |
| `tests/unit/test_hallucination_taxonomy.py` | 13 | Finding classes + contract refusal |
| `tests/unit/test_input_normalizer.py` | 31 | Unicode/NFKC, jargon standardisation |
| `tests/unit/test_json_parser.py` | 15 | Fence/think-block stripping, parse errors |
| `tests/unit/test_network_validator.py` | 20 | Scope containment, CIDR sanity, modes |
| `tests/unit/test_planner_contract.py` | 25 | Contract schema, ports, confidence |
| `tests/unit/test_rbac_guard.py` | 24 | Role matrix pre/post-inference |
| `tests/unit/test_regex_validator.py` | 40 | IP/CIDR/CVE/port/metachar regex |
| `tests/unit/test_schema_validator.py` | 20 | Pydantic intent schema enforcement |
| `tests/unit/test_scope_guard.py` | 10 | Injection re-check + RFC-1918 |
| `tests/unit/test_self_consistency_entropy.py` | 5 | Tier-1 gating + Tier-2 semantic entropy |
| `tests/unit/test_semantic_cache.py` | 37 | Entries, cosine, lookup, store, LRU, stats |
| `tests/unit/test_semantic_cache_adversarial.py` | 4 | Cache hardening, grounding invalidation |
| `tests/unit/test_session_context.py` | 35 | Turns, context injection, TTL, eviction |
| `tests/unit/test_sub_intent_classifier.py` | 46 | Hierarchical sub-intents per intent class |
| `tests/unit/test_uncovered_source_behaviors.py` | 4 | IPv6, Ollama failure, production mode, percentiles |

**Totals:** 434 unit + 72 integration = **506**.

### 2.3 Notes on Execution Quality

- **No live-LLM dependency:** integration fixtures monkeypatch `OllamaInferenceEngine._call_ollama`; the daemon is not required (AGENT.md §Command notes an older live-LLM assumption that no longer applies).
- **Isolation:** `tests/conftest.py` autouse fixture `get_settings.cache_clear()` after every test prevents singleton state pollution.
- **Negative-path log noise:** expected `ERROR`-level `<...>_parse_error` / `<...>_lookup_error` logs appear during deliberately-failing tests (feature_flags, semantic_cache); these are intentional and all tests pass.

---

## 3. Code Coverage (coverage.py, `--cov=src`)

**TOTAL: 76%** — 2421 statements, 582 missed. 17 modules at 100% (omitted from compact output).

| Module | Stmts | Miss | Cover | Assessment |
|---|---|---|---|---|
| `src/api/main.py` | 357 | 141 | **61%** | FastAPI surface under-covered (many routes/edge handlers) |
| `src/audit/audit_logger.py` | 100 | 6 | 94% | OK |
| `src/inference/ollama_inference_engine.py` | 211 | 72 | **66%** | Tier-2/error/disk-cache branches partially uncovered |
| `src/integration/executor_client.py` | 55 | 46 | **16%** | ⚠ C3 client almost untested |
| `src/integration/planner_client.py` | 47 | 33 | **30%** | ⚠ C2 client mostly untested (chain integration) |
| `src/middleware/adversarial_detector.py` | 87 | 1 | 99% | Excellent |
| `src/middleware/semantic_cache.py` | 127 | 7 | 94% | Good |
| `src/middleware/session_context.py` | 111 | 4 | 96% | Good |
| `src/middleware/sub_intent_classifier.py` | 44 | 5 | 89% | Good |
| `src/pipeline/contract_builder.py` | 148 | 104 | **30%** | ⚠ Handoff/refusal paths under-covered |
| `src/pipeline/ire_pipeline.py` | 177 | 49 | 72% | Acceptable; audit/cache-miss branches |
| `src/schemas/intent_schema.py` | 207 | 2 | 99% | Excellent |
| `src/utils/chain_cache.py` | 89 | 68 | **24%** | ⚠ Chain-cache integration under-covered |
| `src/utils/metrics_collector.py` | 47 | 2 | 96% | Good |
| `src/validation/contract_validator.py` | 36 | 1 | 97% | Good |
| `src/validation/json_parser.py` | 28 | 3 | 89% | Good |
| `src/validation/network_validator.py` | 138 | 26 | 81% | Good (IPv6/error branches) |
| `src/validation/regex_validator.py` | 118 | 8 | 93% | Good |
| `src/validation/scope_guard.py` | 56 | 4 | 93% | Good |
| — preprocessing / 100% modules — | alias_resolver 100%, input_normalizer 100%, rbac_guard 100%, schema_validator 100%, planner_contract 100%, hallucination_taxonomy 100%, metrics/logging 100%, all `__init__` 100% |

**Coverage findings:**
1. **High-risk gaps** are in integration/orchestration glue (`src/integration/*`, `contract_builder.py`, `chain_cache.py`) — the C1→C2→C3 handoff layer that the unit-focused suite mostly bypasses.
2. **API layer at 61%** — worthwhile next target; many admin/health/engagement endpoints lack direct route tests.
3. Core safety engine (adversarial 99%, intent_schema 99%, rbac 100%, regex 93%, scope 93%) is strongly verified.

---

## 4. Static Analysis (ruff 0.16.5)

Run: `.venv\Scripts\ruff check src/ tests/ scripts/ config/ --select E,F,I,W,UP,B,SIM,C4,PLC`
Result: **593 findings, zero errors (E9), zero fatal.** No dedicated ruff/flake8 config exists (`pyproject.toml`, `setup.cfg`, `.flake8` absent) — defaults applied.

### 4.1 Top rules by frequency

| Rule | Count | Meaning | Priority |
|---|---|---|---|
| `E501` | 109 | Line > 100 chars | Low (cosmetic) |
| `UP006` | 109 | Use `dict`/`list`/`set` instead of `typing.*` | Low (modernisation) |
| `UP045` | 101 | Use `X \| None` instead of `Optional[X]` | Low (modernisation) |
| `I001` | 70 | Import block unsorted | Low (formatting) |
| `F401` | 44 | **Unused imports** | Medium (housekeeping) |
| `UP035` | 37 | Deprecated `typing.Dict/List/Set` | Low |
| `PLC0415` | 35 | `import` not at top of file | Medium |
| `E402` | 27 | Module-level import not at top | Medium |
| `B904` | 9 | `raise ... from` missing | Medium |
| `W292` | 9 | Missing trailing newline | Low |
| `F841` | 5 | Unused local variable | Medium |
| others | 37 | misc (SIM*, E712, E741, B905…) | Low |

### 4.2 Notes
- The style-modernisation cluster (`UP006`/`UP045`/`UP035`, ~250) is legacy of targeting Python 3.9; `X | None` syntax needs Python 3.10+ so these are *partially intentional*.
- No findings in the correctness class (E9) — the suite's green status is consistent.
- No CI gate exists; recommend adding ruff to CI (even at default rules) to stop E501/I001 drift.

---

## 5. Safety, Security & Data Attributes (verified by tests)

| Attribute | Mechanism | Verification |
|---|---|---|
| Prompt injection | `AdversarialDetector` (3 layers, threshold 0.7, auto-block on critical) | 42 unit + M1 integration-block tests; Exp4 catch 95.6% |
| Role authorization | `RBACGuard` pre/post-inference; analyst↛EXPLOITATION verified in integration | 24 unit + full-stack test |
| Command injection in fields | `RegexValidator` shell-metachar scan `[;&|$\\\`!><]` | 8 dedicated tests |
| CVE hallucination | Syntax check (FABRICATED_CVE→BLOCK) + offline grounding (unindexed→WARN) | 5 grounding tests + Exp4 78.1% |
| Out-of-scope targets | `NetworkArchitectureValidator` CIDR containment + `ScopeGuard` | 20 net-validator tests; warn-mode softens to non-blocking (known gap, §7) |
| Privacy | Audit log stores **SHA-256 hash**, never raw command | dedicated privacy assertion test |
| Human-in-the-loop | ESCALATE queue + `/admin/escalations/{id}/resolve` | integration roundtrip test |
| Rate limiting | slowapi 30 req/min per endpoint | API tests |
| Cache safety | Semantic cache grounding-stamp invalidation, threshold 0.82 runtime | 4 adversarial-hardening tests |

---

## 6. Empirical Evaluation Summary (from `eval/Data Collection/results/`)

Canonical values only (Exp3 second run is authoritative — first run superseded).

| Configuration | Decision Acc % | Catch Rate % | FP Rate % | p50 (ms) | Mean (ms) |
|---|---|---|---|---|---|
| **Full Pipeline (Baseline)** | **68.5** | **79.0** | **42.0** | 16,498 | 28,805 |
| No Scope Guard | 64.0 | 72.0 | 44.0 | 17,355 | 31,404 |
| No RBAC Guard | 74.5 | 64.0 | 15.0 | 16,788 | 28,260 |
| No Network Validator | 68.0 | 80.0 | 44.0 | 15,868 | 27,450 |
| No Hallucination Validator | 59.0 | 62.0 | 44.0 | 15,915 | 26,722 |
| Validation Stack Disabled | 64.0 | 41.0 | 13.0 | 14,291 | 25,198 |
| Self-Consistency Disabled | 67.5 | 80.0 | 45.0 | 13,388 | 11,809 |
| Semantic Cache Disabled | 66.0 | 79.0 | 47.0 | 14,372 | 22,949 |

**Key takeaways:**
- Validation stack = safety backbone (disabling drops catch 79% → 41%, −38 pp).
- Schema+Regex most accuracy-critical (−9.5 pp on removal).
- Semantic cache ≈ free: 379× speedup on hits, no safety impact; cache-hit p50 ≈ 44 ms bounds non-LLM overhead.
- Latency is CPU-inference-bound (~16 s p50), not pipeline-bound — platform caveat documented.
- Exp4 per-category catch: adversarial 95.6% > parameter 87.5% > mismatch 81.2% > CVE 78.1% > contradictory 59.4% > ambiguous 40% > out-of-scope 46.7%.
- **Methodology caveat (from gap register):** all experiments are single runs; no seeds/repeats/CIs yet.

---

## 7. Known Gaps & Risks (curated from `Gaps & Future Works.md` + current audit)

### 7.1 Functional / detection gaps (highest impact first)
| # | Gap | Evidence | Layer |
|---|---|---|---|
| A1 | Out-of-scope targets pass through (esp. DOMAIN targets: 0% catch) | Exp4 46.7% out-of-scope catch | No pre-LLM scope gate; warn-mode default |
| A2 | AMBIGUOUS inputs allowed instead of clarified | 40% catch | No ambiguity gate; `clarification_request` unwritten |
| A3 | Contradictory action–target pairs survive via LLM relabeling | 59.4% catch | No dedicated semantic compatibility validator |
| A4 | Unindexed-but-well-formed CVEs admitted (WARN by policy) | grounding = ~20 entries | Grounding breadth + policy |
| A7 | Novel injection phrasings bypass lexical layer | 95.6% catch → 2 misses/45 | Finite pattern corpus |

### 7.2 Engineering / code-quality
| # | Item | Location |
|---|---|---|
| C1 | ESCALATE policy never emits — 202-queue flow is architectural reserve | `enforcement_policy.py:66-77` |
| C2/C3 | XAI and v2 fields (`secondary_intents`, `clarification_request`, `calibration_method`, `explain`) defined but never written | `intent_schema.py`, `features.yaml` |
| C4 | Fine-tuning / LoRA phase unimplemented (scaffolds only) | `scripts/train_lora.py` et al. |
| C6 | `pipeline_initialized` logged after *every* parse (intended: startup) | `ire_pipeline.py:77-87` |
| C7 | Health-check reaches into `inference_engine._cache` | `ire_pipeline.py:393` |
| C8 | Test-quality debt: some wrong-reason/vacuous tests historically; partially mitigated | README §test audit, gap doc §8 |
| C9 | Env drift: Python 3.9.13 vs README 3.11+; model identity varies (`gemma4:e4b` vs `gemma4:latest` vs `qwen2.5-coder:7b`) | various |
| D1 | Semantic cache threshold: code fallback 0.98 vs runtime-effective 0.82 (`features.yaml:30`) — resolve before publishing | `semantic_cache.py:29`, `features.yaml` |

### 7.3 Evaluation-methodology (publication risk)
- Single-run experiments, no CIs (B1) · confidence calibration unmeasured (B2) · thresholds unswept (B3) · cache-hit quality n=6 too small (B4) · warn-as-BLOCKED convention unstated (B5).

---

## 8. Recommendations (prioritised)

**Tier 1 — engineering hygiene (low effort, immediate value)**
1. Add the 3 new integration files' command to a CI/make target and a ruff gate (default rules) — stop style drift and keep 506 green.
2. Fix `F401` unused imports (44) and `B904 raise…from` (9) in `src/`.
3. Add route-level tests for uncovered API endpoints (`/admin/*`, `/engagement/scope`, `/session` delete) to lift `src/api/main.py` from 61%.
4. Add tests for `chain_cache.py` (24%) and `contract_builder.py` (30%); these are the C1→C2/C3 handoff — treat as the most valuable coverage investment.

**Tier 2 — functional gap closures (evidence-backed)**
5. Pre-LLM deterministic scope gate for IP/CIDR/domain literals (closes A1 = ~35% of Exp4 misses).
6. Promote `OUT_OF_SCOPE_TARGET`/`TARGET_TYPE_MISMATCH` to block in a strict enforcement profile (pure policy change, no new code).
7. Wire the dormant `clarification_request` for AMBIGUOUS outcomes (A2).
8. Resolve the 0.98-vs-0.82 cache-threshold discrepancy (§7.2 D1) and document the effective value.

**Tier 3 — publication rigor**
9. Multi-seed repeated runs + confidence intervals per `Data_Collection_Plan.md`.
10. Confidence calibration study (ECE) for the self-reported Tier-1 score driving the γ=0.7 gate.
11. Threshold sensitivity Pareto sweeps (cache θ, adversarial τ, gate γ, entropy bands).

---

## 9. Verification Commands

```powershell
# Full suite
.venv\Scripts\python.exe -m pytest -q
# Coverage report
.venv\Scripts\python.exe -m pytest tests --cov=src --cov-report=term
# Lint scan
.venv\Scripts\ruff check src/ tests/ scripts/ config/
# Targeted component integration
.venv\Scripts\python.exe -m pytest tests/integration/test_integration_pipeline_full_stack.py -q
```

*Report compiled from: pytest run 2026-08-30 (506 passed), coverage.py 7.10.7, ruff 0.16.5, `eval/Data Collection/results/exp3_summary.json`, and `IRE-Doc/Gaps & Future Works.md`.*