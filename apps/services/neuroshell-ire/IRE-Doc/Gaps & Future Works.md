# Gaps & Future Works — neuroshell-ire

**Purpose:** Consolidated register of every known gap (detection, evaluation-methodology, engineering, configuration) plus a prioritized future-work roadmap. Source-traceable; feeds directly into the paper's *Limitations* and *Future Work* sections.
**Canonical evidence base:** `IRE-Doc/research-extraction.md` (§7 results inventory, §7.0 hardware conditions). All experiment figures below are canonical-run values.
**Compiled:** 2026-08-26

---

## Part I — Gaps

### A. Detection-capability gaps (measured, with root causes)

Ranked by impact on flawed-input catch rate. Evidence: Exp3 baseline per-category + Exp4 (250-record canonical run).

| # | Gap | Evidence (canonical) | Root cause (layer) | Candidate fix |
|---|-----|----------------------|--------------------|---------------|
| A1 | **Out-of-scope targets pass through** | Catch 46.7% (21/45) in Exp4; 45% in Exp3 baseline; **0% for DOMAIN targets** in Exp1 | No scope check before inference (`llm_no_scope_detection`, 24/68 = 35% of Exp4 misses); S6B containment skips DOMAIN/URL/HOSTNAME types (`network_validator.py:_is_in_scope` early-True); warn-mode severity (`engagement_mode="warn"` default) | Pre-LLM deterministic scope gate; DNS-resolve domains to IPs before containment test |
| A2 | **AMBIGUOUS inputs allowed instead of clarified** | Ambiguous catch 40% (8/20) Exp4; 2/5 Exp3 baseline; AMBIGUOUS intent returned as success with confidence < 0.5 passes schema | No dedicated ambiguity gate in pipeline; `clarification_request` field defined but never written | Block-or-clarify policy for AMBIGUOUS outcomes; wire the clarification loop |
| A3 | **Contradictory action–target pairs survive via LLM relabeling** | Catch 59.4% (19/32) Exp4; 75% (9/12) Exp3 baseline; 11 misses = model emitted an internally-consistent but semantically wrong pairing | No semantic action↔target compatibility validator exists (taxonomy class CONTRADICTORY_ACTION_TARGET has no dedicated detector) | Rule/ontology table of valid intent×target-type pairs; or LLM verifier pass |
| A4 | **Ungrounded-but-well-formed CVEs admitted** | Fabricated-CVE catch 78.1% (25/32) Exp4; grounding miss = WARN by policy (`UNGROUNDED_CONFIDENCE` → warn) | Grounding dataset only 20 entries; unindexed CVE treated as plausible zero-day (`enforcement_policy.py`) | Expand grounding (CISA KEV refresh); optional strict-mode severity flip; date-bounded plausibility check (CVE year vs knowledge cutoff) |
| A5 | **Target-type mismatches under-enforced** | Catch 81.2% (26/32) Exp4; 6 misses = mismatch not flagged at all | Type-consistency checks live in S6B Step 1 at warn severity by default; some mismatch shapes escape both S5 and S6B patterns | Promote TARGET_TYPE_MISMATCH to block; add value-shape predicates per declared type |
| A6 | **Parameter fabrication edge cases** | Catch 87.5% (28/32) Exp4; 4 misses where LLM normalized/dropped the bad parameter | Detection depends on the parameter surviving into structured output; LLM can silently discard malformed ports | Input-side numeric-literal scan (pre-inference) comparing mentioned numbers vs extracted fields |
| A7 | **Sophisticated prompt injections bypass lexical layer** | Adversarial catch 95.6% (43/45) Exp4; 2 unclassified misses | Pattern sets are finite; novel phrasings depend on LLM self-rejection alone | Embedding-similarity injection detector; periodic red-team expansion of pattern corpus |

### B. Evaluation-methodology gaps

| # | Gap | Detail | Consequence |
|---|-----|--------|-------------|
| B1 | **Single-run experiments** | Every result is one run; LLM sampling nondeterminism unquantified; no seeds/repeats/CIs. Own plan (`Data_Collection_Plan.md` §213) prescribes 3–5 seeded repeats — implemented nowhere | Headline deltas carry no error bars; reviewer objection expected |
| B2 | **Confidence calibration unmeasured** | Tier-1/Tier-2 gate trusts self-reported confidence c₁ (γ=0.7); no ECE/reliability analysis; `calibration_method` schema field unwritten | Gate threshold may be systematically miscalibrated without any test failing |
| B3 | **Thresholds lack sensitivity analysis** | Cache θ=0.82 (runtime), adversarial τ=0.70, gate γ=0.7, entropy bands {0.3, 0.8} are single operating points | Cannot claim robustness; Pareto curves unknown |
| B4 | **Cache-hit quality sample too small** | n=6 hits in baseline run; hit correctness 3/6 vs miss 126/194 — statistically meaningless comparison | "Cache preserves accuracy" claim currently unsupported; needs dedicated repeat-query benchmark |
| B5 | **Warn-as-BLOCKED scoring convention** | Eval classifiers (`diagnose.py`, `category_metrics.py`) count warn findings as BLOCKED | Catch rates conflate "hard-blocked" with "warned"; paper must define which; strict-vs-warn comparisons shift definitions |
| B6 | **Benchmark contamination history** | Inference disk cache corrupted Exp1 Config-4 latency once (p50 678ms vs true 32.8s), fixed in `3a125e4` | Any future benchmark must flush/namespace caches per condition |
| B7 | **RBAC coverage hole in dataset** | Golden roles: analyst 140 / operator 60 / viewer 0 — pre-inference viewer fast-fail never exercised by experiments | M2 path validated only by unit tests; add viewer-role rows if RBAC is a paper claim |
| B8 | **Single-machine, CPU-only measurements** | All latencies from one ultrabook, Ollama CPU inference (§7.0 of extraction doc); ~44ms total non-LLM overhead proven via cache-hit p50 | Latency figures are platform-bound, not pipeline-inherent; GPU comparison missing |

### C. Engineering / code-level gaps

| # | Gap | Location | Note |
|---|-----|----------|------|
| C1 | ESCALATE path dormant | `enforcement_policy.py:66-77` | Policy never emits escalate; full 202-withholding flow + admin resolve API exist but unreachable until policy change |
| C2 | XAI scaffolding inert | `intent_schema.py:254-271`, `features.yaml:18` | `explain` request flag accepted but unused; XAIBlock/XAIToken have no producer |
| C3 | Dead v2 response fields | `secondary_intents`, `clarification_request`, `calibration_method` | Defined, documented, never populated |
| C4 | Fine-tuning phase unimplemented | `scripts/train_lora.py` et al. TODO stubs; `models/`, `data/synthetic/` empty | LoRA config fully specified but Phase 2 not started |
| C5 | Reserved flags without code | `uncertainty_estimation`, `continual_learning`, `speculative_decoding` (`features.yaml:21-23`) | Flag surface suggests capabilities that don't exist |
| C6 | Misplaced init log | `ire_pipeline.py:77-87` | `pipeline_initialized` emitted after every parse inside `_log_audit_findings` |
| C7 | Private-member reach-in | `ire_pipeline.py:393` health_check reads `_cache` | Encapsulation break; harmless but fragile |
| C8 | Test-suite quality debt | Wrong-reason tests (uniform-random-vector cosine test, assertion-free domain test, vacuous think-block tests), isolation hazards (`test_hallucination_taxonomy.py` settings mutation), xdist SQLite collision risk | Partially mitigated (`tests/conftest.py` autouse reset, mocked Ollama in integration fixtures); remainder catalogued in extraction doc §8 |
| C9 | Environment drift | venv Python 3.9.13 vs README 3.11+; settings default `gemma4:e4b` vs `.env` `gemma4:latest` vs experiment `qwen2.5-coder:7b` | Reproducibility friction; pin exact versions in paper |

### D. Configuration / documentation gaps

| # | Gap | Detail |
|---|-----|--------|
| D1 | Semantic-cache threshold conflict | Code fallback 0.98 (`semantic_cache.py:29`) vs runtime-effective 0.82 (`features.yaml:30`); earlier docs claimed 0.98 tuned. Must resolve before reporting |
| D2 | spaCy declared, unused | `requirements.txt` + installed by launcher; zero runtime imports — remove or justify |
| D3 | jsonschema declared, unused at runtime | Pydantic does the validation; draft-07 schema file maintained as artifact only — clarify its contract role |
| D4 | `min_cidr_prefix` defined, unread | `settings.py:80-83` exposed via `/engagement/scope` but no validator consumes it |
| D5 | Doc drift | README says 14 lexical patterns (source has 15); README architecture omits middleware; test-count splits drifted between internal tallies (434+48 measured = 482) |

---

## Part II — Future Works

Prioritized roadmap. Tier 1 = cheap, high-yield, evidence-backed. Tier 2 = methodological must-dos for publication rigor. Tier 3 = research extensions.

### Tier 1 — Direct gap closures

1. **Pre-LLM deterministic scope gate** — extract IP/CIDR/domain literals post-normalization, test against Ω before inference. Addresses A1 = 35% of all Exp4 misses; near-zero latency cost. *(closes A1 partially)*
2. **Domain-aware scope checking** — resolve DOMAIN/URL → IPs, then contain. Closes the 0%-domain blind spot and threat-model T4 residual. *(closes A1 remainder)*
3. **Strict/segregate enforcement profiles** — flip `OUT_OF_SCOPE_TARGET`/`TARGET_TYPE_MISMATCH` to block via existing EnforcementPolicy (no code change); publish research-vs-strict ablation. *(addresses A1, A5 severity dimension)*
4. **Intent×target compatibility table** — static ontology (e.g., PASSIVE_RECON ↛ PORT target) wired as validator; catches relabeled contradictions deterministically. *(A3)*
5. **Ambiguity gate** — route AMBIGUOUS outcomes to clarification using the dormant `clarification_request` field; optionally HTTP 409-style contract. *(A2)*

### Tier 2 — Publication-rigor work

6. **Multi-seed repeated runs + confidence intervals** — 3–5 repeats per condition per `Data_Collection_Plan.md`; report mean±CI for every headline number. *(B1)*
7. **Calibration study** — reliability diagrams / ECE for c₁ by intent class; recalibrate γ or replace with calibrated score; populate `calibration_method`. *(B2)*
8. **Threshold sensitivity sweeps** — θ ∈ [0.82, 0.98], τ, γ, entropy bands → catch/FP/latency Pareto plots. *(B3)*
9. **Cache-quality benchmark** — adjudicated repeat-query workload (n ≫ 6) measuring false-hit rate and hit accuracy; also settles the 0.82-vs-0.98 question empirically. *(B4, D1)*
10. **Metric-definition harmonization** — fix one decision classifier (warn=blocked vs warn=allowed) across all reported tables; state it in the paper. *(B5)*

### Tier 3 — Research extensions

11. **LoRA fine-tuning (Phase 2)** — execute the specified plan (20k synthetic examples, Gemma-4-27b-it NF4, r=16, target metrics incl. p95 ≤ 2000 ms). *(C4; attacks B8 latency ceiling)*
12. **Embedding-based injection detector** — complement lexical patterns for novel phrasings; measure against A7 residue. 
13. **XAI activation** — token-attribution producer behind existing `xai` flag/schema; adds interpretability evidence.
14. **Compound-intent extraction** — populate `secondary_intents` for multi-action commands.
15. **GPU hardware comparison** — same baseline config on GPU host to separate pipeline latency from platform latency. *(B8)*
16. **Remaining planned experiments 5–8** — per `Data_Collection_Plan.md`.
17. **Grounding governance** — scheduled KEV refresh + dataset versioning surfaced in responses/audit. *(A4 sustainment)*
18. **Engineering hygiene batch** — C1 (wire a real ESCALATE policy), C2/C3 (implement or delete dead surfaces), C6/C7 fixes, C8 test remediation, C9 version pinning.

---

## Part III — Traceability map (gap → evidence → fix → paper section)

| Paper section | Draws on |
|---|---|
| Threat Model | Extraction §1.4 (T1–T4 residuals = A1, A3, A7) |
| Methodology | Extraction §4.1–4.3; scoring conventions (B5 declared here) |
| Evaluation setup | Extraction §7.0 (hardware), §7.2 (dataset composition incl. B7), reproducibility notes |
| Results caveats | A-table figures; B4 cache caveat; B6 contamination disclosure |
| Discussion / Limitations | Part I verbatim source |
| Future Work | Part II tiers, ordered |

> Maintenance rule: when a gap is fixed, move its row to a "Resolved" appendix with the commit hash — do not delete history; the paper's limitations section should cite resolved items as "addressed in revision" only if they were claimed in the original submission.

--------------------------------------------------------------------------------------------------------

## 8. Limitations & Known Issues

### 8.1 Documented in-repo
- Test-quality issues identified during a prior code audit of the suite: wrong-reason tests (e.g., uniform-random-vector cosine "best match" test in `tests/unit/test_semantic_cache.py`; assertion-free domain test in `tests/unit/test_regex_validator.py`; think-block parser tests passing vacuously in `tests/unit/test_json_parser.py`), isolation hazards (settings mutation without restore in `tests/unit/test_hallucination_taxonomy.py`; incomplete reset in `tests/unit/test_network_validator.py`), tautological assertions, and SQLite collision risk under xdist (`data/audit_log.db`). Mitigations applied so far: autouse settings-reset fixture (`tests/conftest.py`), mocked Ollama in integration fixtures. Remaining fixes were proposed but not confirmed for implementation.
- Benchmark contamination incident: inference disk cache served stale responses, corrupting Exp1 Config-4 latency (p50 678 ms vs true 32.8 s); corrected by re-run committed as `3a125e4` (see refreshed `eval/Data Collection/results/exp1_full_pipeline_qwen_2.5.json`).
- Latency far exceeds interactive budgets: p50 ≈ 16 s, p95 ≈ 70 s full pipeline (`exp3_comparison.md`) — measured under **CPU-only inference** on ultrabook hardware (§7.0), so figures reflect the test platform, not a GPU deployment; fine-tuning target p95 ≤ 2000 ms not yet approached (`lora_config.yaml:53-59`).
- **Statistical rigor gap:** every experiment is a single run — no seeds, no repetitions, no confidence intervals; LLM sampling nondeterminism is unquantified. (The project's own `Data_Collection_Plan.md` specifies 3–5 seeded repeats per condition — implemented nowhere.) Reviewers should expect this objection; either run repeats or scope claims accordingly.
- **Confidence calibration unexamined:** the entire Tier-1/Tier-2 gate rests on the model's *self-reported* confidence (c₁), yet no calibration measurement (ECE, reliability diagram) exists, and the schema's `calibration_method` field has no writer. c₁ could be systematically miscalibrated without any test failing.
- **Entropy band thresholds arbitrary:** H < 0.3 / H > 0.8 bands (and cache θ, adversarial τ, gate γ) have no sensitivity analysis backing them.
- **Latency budget evidence (supports "validation ≈ free" claim):** cache-hit p50 of 44 ms bounds total non-LLM overhead (embedding + all validators + assembly) at ~44 ms — i.e., >99% of mean pipeline latency (≈28.8 s) is LLM inference, not the validation stack (`checkpoint_ablation_full_pipeline_baseline.json`).

### 8.2 Observed in code during this analysis
- **Warn-mode safety gap:** with default `engagement_mode="warn"`, out-of-scope targets and type mismatches produce warnings but ALLOW decisions — directly responsible for Exp4's lowest catch rates (out_of_scope 46.7%). Files: `network_validator.py:180-186`, `enforcement_policy.py:58-64`.
- **Ambiguous handling gap:** AMBIGUOUS intent passes through as success unless confidence rules trip; 12/20 ambiguous records ALLOWED in Exp4. No dedicated ambiguity blocker exists (`pipeline` has no AMBIGUOUS-specific gate; cf. `metrics.py` counting logic).
- **Misplaced init log:** `pipeline_initialized` is logged inside `_log_audit_findings`, i.e., after *every* parse, not at startup (`ire_pipeline.py:77-87`).
- **Private-member reach-in:** `health_check()` reads `inference_engine._cache` directly (`ire_pipeline.py:393`).
- **`explain` flag accepted but unused** in `ParseRequestV2` (`intent_schema.py:372-375`) — XAI fields (`XAIBlock`, `XAIToken`) defined but no producer; `xai` flag permanently false (`features.yaml:18`).
- **Dead/unpopulated v2 fields:** `secondary_intents`, `clarification_request`, `calibration_method` have no writer anywhere in `src/` (grep-verified during this analysis).
- **Unimplemented scaffolds:** `scripts/train_lora.py`, `clean_dataset.py`, `evaluate_model.py` contain only TODO headers (Phase 7); flags `uncertainty_estimation`, `continual_learning`, `speculative_decoding` have no implementing code (`features.yaml:21-23`); `models/`, `notebooks/`, `data/raw/`, `data/synthetic/` empty (`.gitkeep` only).
- **Environment drift:** venv runs Python 3.9.13 (verified: `.venv\Scripts\python.exe --version`) vs README's 3.11+ requirement (`README.md:65`); settings default model `gemma4:e4b` (`settings.py:27`) vs `.env` runtime `gemma4:latest` vs experiments' `qwen2.5-coder:7b`.
- **Escalate path defined, rarely exercised:** policy engine supports ESCALATE and API has full queue, but current policy mapping never emits `escalate` severity (only BLOCK/WARN per `enforcement_policy.py:66-77`), so the 202 flow is effectively dormant until a future policy change.

---

## 9. Future Work Candidates

Grounded in code/TODOs/docs:

1. **LoRA fine-tuning (Phase 2)** — fully specified config awaiting dataset + training scripts: 20k synthetic examples, Gemma-4-27b-it NF4, r=16 (`config/lora_config.yaml`; stub scripts).
2. **Enforce-mode / per-engagement policy profiles** — flip `engagement_mode="strict"` or promote TARGET_TYPE_MISMATCH/OUT_OF_SCOPE severities to recover Exp4 misses; add per-deployment policy presets (`config/settings.py:67-83`, exp4 proposed fixes).
3. **Pre-LLM deterministic scope gate** — Exp4's dominant miss root cause (24 cases) is public targets reaching inference; a cheap CIDR pre-check before S3 would close most of it (evidence: `exp4_hallucination_report.md` root-cause distribution).
4. **AMBIGUOUS handling policy** — clarification-request loop using the already-defined-but-unwritten `clarification_request` field.
5. **Activate XAI** — implement integrated-gradients attribution behind the existing `xai` flag/schema (`features.yaml:18`, `intent_schema.py:254-271`).
6. **Populate compound-intent support** — wire `secondary_intents` producer for multi-action commands.
7. **Monte-Carlo uncertainty / continual learning / speculative decoding** — flags reserved Phase 3 (`features.yaml:21-23`).
8. **Remaining paper experiments 5–8** per `IRE-Doc/Data_Collection_Plan.md` (phases beyond Exp4).
9. **Test-robustness remediation** — fix the remaining wrong-reason tests and isolation hazards identified in §8 (files listed there).
10. **Automated grounding refresh governance** — scheduler/verification around the manual KEV updater, plus grounding-version stamping surfaced in responses.
11. **Confidence-calibration study** — measure ECE / reliability of c₁ against empirical correctness per intent class; recalibrate or replace the self-reported confidence that drives the γ=0.7 gate (schema's `calibration_method` field is the natural home for reporting the chosen method).
12. **Threshold sensitivity analysis** — sweep cache θ ∈ {0.82…0.98}, adversarial τ, gate γ, and entropy bands {0.3, 0.8}; report catch/FP/latency Pareto curves instead of single operating points.
13. **Multi-seed repeated runs with confidence intervals** — 3–5 seeded repeats per condition (as `Data_Collection_Plan.md` already prescribes) so headline deltas carry error bars.
14. **Domain-aware scope checking** — resolve DOMAIN/URL targets to IPs before scope containment; closes the out_of_scope 0% gap and the T4 residual in the threat model.
15. **Dedicated cache-quality benchmark** — repeat-query workload with adjudicated ground truth to quantify false-hit rate and hit accuracy at n ≫ 6 (current evidence base is too small, cf. Results-draft §7.6 caveat).

---

## 10. Needs Clarification / Assumptions To Verify

Items where sources conflict or are silent — **verify before asserting in the paper**:

1. **Effective semantic-cache threshold.** Code fallback default is **0.98** (`semantic_cache.py:29`), but `config/features.yaml:30` sets **`semantic_cache_threshold: 0.82`**, which overrides at runtime (also note: earlier internal draft docs claimed 0.98 was the tuned value). Which value do you want reported? (Runtime-effective answer today: 0.82.)
2. **Test counts.** Direct source count is 434 sync unit + 48 async integration = 482; an earlier internal tally recorded 436/46. Publish the measured split.
3. **Adversarial pattern counts.** Some draft documents say 14 lexical + 7 structural (e.g., `IRE-Doc/Results_Section_Draft.md`); source has **15 lexical** tuples (`adversarial_detector.py:41-72`). Confirm final numbers before publishing.
4. ~~**Exp3 numeric discrepancies.**~~ **RESOLVED 2026-08-26:** Exp3 was run twice; the user confirmed the **second run is canonical**. Canonical table = `eval/Data Collection/results/exp3_comparison.md` + `exp3_summary.json` (baseline DAcc 68.5%, catch 79.0%, FP 42.0%; all 8 checkpoints verified 200/200, 0 errors, sequential timestamps Aug 24 23:56 → Aug 25 11:44). The first-run figures have been removed everywhere and marked superseded. Cite only the second-run numbers in the paper.
5. **Model identity.** README/docker-compose default `gemma4:e4b`; `.env` runtime sets `gemma4:latest`; experiments primarily used `qwen2.5-coder:7b`. State clearly which model produced which reported numbers.
6. **spaCy's actual role.** Listed in stack and installed by launcher, but no runtime import found. Either remove from stack claims or document intended use (was it planned for NER that regex replaced?).
7. **`jsonschema` library usage.** Declared in requirements and a draft-07 schema file is maintained, but validators use Pydantic. Is `ire_intent_schema.json` published as an external contract artifact (for Component-02 consumers)? If so, worth stating; otherwise clarify why the dep exists.
8. **Institution/anonymization placeholders.** README contains `[REDACTED]` student ID and institution — confirm final paper attribution details.
9. **`min_cidr_prefix` usage.** Defined in settings (`settings.py:80-83`) and exposed via `/engagement/scope`, but no validator reads it (only `max_cidr_prefix` enforced). Intended future bound or oversight?
10. **Escalation severity trigger.** No current HallucinationClass maps to ESCALATE. Is human-review escalation planned for specific classes (which?), or kept as architectural reserve?
11. **Golden-dataset ground truth sign-off.** Older `dataset_draft.jsonl` carried an explicit "GROUND TRUTH PENDING USER SIGN-OFF" header; confirm golden_dataset.jsonl labels are now authoritatively reviewed (needed for evaluation-section credibility).
12. **Cache-threshold effect on Exp3 cache metrics.** Given item 1, the reported 6-hit/0.375%-hit-rate figures were collected under whichever threshold was active then — recheck before quoting hit-rate numbers.

---