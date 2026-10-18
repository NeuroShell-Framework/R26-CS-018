# Experiment 2: Model Head-to-Head (Gemma 4 vs Qwen 2.5 Coder 7B)

**Dataset:** eval/golden_dataset.jsonl — 900 golden records
**Design:** gemma4:latest vs qwen2.5-coder:7b, identical 900 records, both through the full pipeline
**Source:** IRE-Doc/NeuroShell_IRE_Test_New_Results.md (§ Experiment 2)

## Purpose
Compare two locally-hosted LLMs on the same dataset through the full validation pipeline.

## Overall Metrics

| Metric | Gemma 4 | Qwen 2.5 Coder | Delta |
| :--- | :---: | :---: | :---: |
| **Intent Accuracy** | 86.0% | 82.0% | −4.0pp |
| **Hallucination Catch Rate** | 72.0% | 64% | −8.0pp |
| **False Positive Rate** | 14.0% (28 FPs) | 15.0% (30 FPs) | +1.0pp |
| **p50 (ms)** | 27,650 | 32,755 | +5,105 (~18% slower) |
| **p95 (ms)** | 148,347 | 177,666 | +29,319 (~19.8% slower) |
| **Mean (ms)** | 39,555 | 45,208 | +5,653 (~14.3% slower) |

## Per-Intent Accuracy

| Intent | Gemma % | Qwen % | Δ (pp) | Winner |
| :--- | :---: | :---: | :---: | :---: |
| AMBIGUOUS | 83.3 | 83.3 | 0.0 | Tie |
| DIRECTORY_BRUTEFORCE | 100.0 | 100.0 | 0.0 | Tie |
| EXPLOITATION | 100.0 | 90.9 | −9.1 | Gemma |
| NETWORK_SCAN | 76.5 | 70.6 | −5.9 | Gemma |
| PASSIVE_RECON | 90.9 | 90.9 | 0.0 | Tie |
| PASSWORD_ATTACK | 100.0 | 100.0 | 0.0 | Tie |
| REJECTED | 0.0 | 0.0 | 0.0 | Tie |
| SERVICE_ENUMERATION | 92.3 | 92.3 | 0.0 | Tie |
| VULNERABILITY_AUDIT | 93.3 | 100.0 | +6.7 | Qwen |

## Per-Category Decision Accuracy (%)

| Category | Gemma | Qwen | Δ |
| :--- | :---: | :---: | :---: |
| well_formed | 86.0 | 85.0 | −1.0 |
| adversarial_injection | 100.0 | 100.0 | 0.0 |
| ambiguous | 80.0 | 80.0 | 0.0 |
| hallucination_contradictory_action_target | 16.7 | 8.3 | −8.3 |
| hallucination_fabricated_cve | 33.3 | 41.7 | +8.3 |
| hallucination_fabricated_parameter | 91.7 | 75.0 | −16.7 |
| hallucination_target_type_mismatch | 33.3 | 33.3 | 0.0 |
| out_of_scope | 0.0 | 0.0 | 0.0 |
| rbac_violation | 100.0 | 100.0 | 0.0 |

---

## Key Findings

1. **Gemma leads Qwen on overall accuracy**: 86.0% vs 82.0% (−4.0pp), driven mostly by EXPLOITATION (−9.1pp) and NETWORK_SCAN (−5.9pp); Qwen wins only VULNERABILITY_AUDIT (+6.7pp).
2. **Hallucination catch favors Gemma**: 72.0% vs 64.0% (−8.0pp), widest on fabricated_parameter (−16.7pp).
3. **False positives are near-identical**: 28 FPs (Gemma) vs 30 FPs (Qwen), +1.0pp — both conservative, all FPs are rejections.
4. **Qwen is ~18% slower at p50**: +5,105 ms (27,650 vs 32,755 ms); p95 +29,319 ms, mean +5,653 ms.
5. **Adversarial, RBAC, ambiguous, out-of-scope edge cases match**: within-family agreement on AMBIGUOUS (tie), adversarial_injection/rbac_violation (100%), and out_of_scope (0% for both).