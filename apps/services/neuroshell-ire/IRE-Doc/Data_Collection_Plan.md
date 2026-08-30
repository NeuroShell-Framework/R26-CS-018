# Data Collection Plan for S-Tier Research Paper

## Overview

This document outlines the complete data collection strategy for producing an S-tier research paper on the neuroshell-ire NLU pipeline. Each experiment maps to a specific paper section and produces quantifiable evidence.

---

## Phase 1: Baseline & Model Comparison (Experiments 1-2)

### Experiment 1 — Raw LLM Baseline vs Full Pipeline

**Purpose:** Prove the validation pipeline adds value over raw LLM inference.

| What | How | Output File |
|---|---|---|
| Raw Gemma baseline metrics | `run_baseline.py` with `golden_dataset.jsonl` | `.baseline_summary.json` |
| Raw Qwen baseline metrics | Modify `run_baseline.py` to use `qwen2.5-coder:7b` | `.baseline_summary_qwen.json` |
| Full pipeline (Gemma) | `diagnose.py golden_dataset.jsonl` | `full_pipeline_debug.jsonl` |
| Full pipeline (Qwen) | Same with Qwen config | `full_pipeline_qwen_debug.jsonl` |

**Metrics to collect:** accuracy, hallucination catch rate, false positive rate, p50/p95 latency, per-category breakdown.

**Paper section:** Evaluation

### Experiment 2 — Model Head-to-Head (Gemma 4 vs Qwen 2.5 Coder 7B)

**Purpose:** Compare two locally-hosted models on identical inputs.

Same 200 records, both models, compare:
- Intent accuracy per intent type
- Latency distribution (p50, p95, p99)
- Hallucination catch rate
- Which model handles adversarial inputs better
- Semantic entropy / uncertainty calibration

**Paper section:** Evaluation, Model Comparison

---

## Phase 2: Ablation Study (Experiment 3)

### Experiment 3 — Component Contribution

**Purpose:** Prove each validation layer is necessary, not just decoration.

Run `ablation.py` with golden dataset. Existing configs:

| Config | What it proves |
|---|---|
| Full Pipeline | Upper bound performance |
| Validation Stack Disabled | Shows total validation layer contribution |
| Self-Consistency Disabled | Shows Tier-2 sampling contribution |
| Semantic Cache Disabled | Shows cache latency savings |

Additional configs to add:

| Config | What it proves |
|---|---|
| No Scope Guard | Shows scope enforcement contribution |
| No RBAC Guard | Shows access control contribution |
| No Network Validator | Shows CIDR/scope validation contribution |
| No Hallucination Validator | Shows CVE/parameter checking contribution |

**Output:** Waterfall chart data showing incremental improvement per layer.

**Paper section:** Ablation Study

---

## Phase 3: Hallucination Deep-Dive (Experiment 4)

### Experiment 4 — Per-Hallucination-Class Analysis

**Purpose:** Show which hallucination types are hardest to detect.

Use `diagnose.py` output, filter by category:

| Category | Expected Catch | Actual Catch | Missed Cases |
|---|---|---|---|
| fabricated_cve | 100% | ? | List misses |
| target_type_mismatch | 100% | ? | List misses |
| contradictory_action_target | 100% | ? | List misses |
| fabricated_parameter | 100% | ? | List misses |
| adversarial_injection | 100% | ? | List misses (7 regex-bypass) |
| out_of_scope | 100% | ? | List misses |

For each missed case, document:
- Why it was missed (which validation layer failed)
- What would catch it (proposed improvement)

**Paper section:** Hallucination Taxonomy, Error Analysis

---

## Phase 4: Adversarial Robustness (Experiment 5)

### Experiment 5 — Injection Resistance

**Purpose:** Prove defense-in-depth works even when individual layers fail.

25 adversarial records, split by detection method:

| Detection Layer | Caught | Missed |
|---|---|---|
| Regex (scope_guard) | ? | ? |
| LLM rejection (inference) | ? | ? |
| RBAC guard | ? | ? |
| Combined | ? | ? |

**Paper section:** Adversarial Analysis

---

## Phase 5: Latency Profiling (Experiment 6)

### Experiment 6 — Performance Budget

**Purpose:** Show the pipeline is operationally viable (under 2s p95).

From `diagnose.py` output, collect:
- Latency histogram (bucket into 0-500ms, 500-1000ms, 1000-2000ms, 2000ms+)
- Latency by record category (well-formed vs flawed)
- Latency with cache hit vs cache miss
- Latency with self-consistency (Tier 2) vs without

**Paper section:** Performance

---

## Phase 6: Fine-Tuning (Experiment 7)

### Experiment 7 — Before/After Fine-Tuning

**Purpose:** Show fine-tuning improves domain-specific performance.

| Step | How |
|---|---|
| Format golden dataset -> SFT pairs | Script: input -> expected JSON output |
| Fine-tune Gemma on 200 records | Ollama Modelfile or unsloth |
| Evaluate fine-tuned model | Same eval pipeline |
| Compare: base vs fine-tuned | Same metrics |

**Metrics to collect:** improvement delta per metric, which categories improve most.

**Paper section:** Fine-Tuning Results

---

## Phase 7: Error Analysis (Experiment 8)

### Experiment 8 — Failure Taxonomy

**Purpose:** Show you understand why things fail, not just that they fail.

From all diagnostic runs, extract failure cases:

| Failure Type | Count | Example | Root Cause |
|---|---|---|---|
| Intent confusion | ? | NETWORK_SCAN vs SERVICE_ENUMERATION | LLM ambiguity |
| Target extraction fail | ? | URL parsed as domain | Regex gap |
| False rejection | ? | Valid command blocked | Scope guard too strict |
| False acceptance | ? | Flawed command passed | Validation gap |
| CVE hallucination pass-through | ? | Fake CVE not caught | Missing from grounding DB |

**Paper section:** Discussion, Limitations

---

## Summary: Experiment-to-Paper Mapping

| Experiment | Data Collected | Paper Section |
|---|---|---|
| 1. Baseline | Raw LLM accuracy, catch rate | Evaluation |
| 2. Model Comparison | Gemma vs Qwen metrics table | Evaluation |
| 3. Ablation | Per-component contribution | Ablation Study |
| 4. Hallucination Deep-Dive | Per-class catch rates | Hallucination Taxonomy |
| 5. Adversarial Robustness | Injection detection layers | Adversarial Analysis |
| 6. Latency Profiling | Distribution, cache impact | Performance |
| 7. Fine-Tuning | Before/after delta | Fine-Tuning |
| 8. Error Analysis | Failure taxonomy | Discussion |

---

## Visualizations Required

| Chart | Purpose | Data Source |
|---|---|---|
| Confusion matrix heatmap | Shows intent confusion patterns | Experiment 1/2 |
| Bar chart: catch rate per hallucination class | Shows which hallucinations are hardest | Experiment 4 |
| Ablation waterfall chart | Shows component contribution | Experiment 3 |
| ROC curve: baseline vs full pipeline | Shows overall improvement | Experiment 1 |
| Latency histogram | Shows operational viability | Experiment 6 |
| Category distribution of golden dataset | Shows evaluation breadth | Dataset stats |
| Adversarial detection layer breakdown | Shows defense-in-depth value | Experiment 5 |

---

## What to Build First

The eval scripts mostly exist. Required changes:

1. **Update `run_pipeline.py`** — default dataset to `golden_dataset.jsonl`
2. **Add Qwen config to `run_baseline.py`** — swap model name, separate cache file
3. **Add per-layer ablation configs to `ablation.py`** — scope guard, RBAC, network validator, hallucination validator
4. **Build `collect_all_results.py`** — runs all experiments, writes results to `eval/results/` directory
5. **Build `generate_charts.py`** — produces all visualization data from results

---

## Statistical Rigor

- Run each experiment 3-5 times with different random seeds
- Report mean +/- std for all metrics
- Use paired statistical tests where applicable
- This separates rigorous work from "we ran it once and got 74%"
