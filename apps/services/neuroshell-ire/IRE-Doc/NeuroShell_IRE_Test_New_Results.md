**NeuroShell IRE - Test Suite & Evaluation Results**

Intent Recognition Engine (Component 01) --- Empirical Results Reference

*Source: research extraction dated 2026-08-26. Tables reproduced from
eval harness output (§7 of the extraction).*

# Experimental Setup

All experiments (Exp1--Exp4) ran on a single consumer laptop with
CPU-only LLM inference (no discrete GPU).

***Hardware & Software***

| Component | Specification |
| :--- | :--- |
| **Machine** | ASUS VivoBook X513EA (ultrabook) |
| **CPU** | Intel Core i5-1135G7, 4 cores / 8 threads, 2.4 GHz base |
| **GPU** | Intel Iris Xe (integrated only --- no discrete GPU) |
| **RAM** | 24 GB DDR4-3200 |
| **Storage** | 256 GB NVMe SSD + 1 TB HDD |
| **OS** | Windows 11 Home (build 10.0.26200) |
| **Inference runtime** | Ollama v0.32.15 (local daemon, CPU execution) |
| **Models** | qwen2.5-coder:7b (4.7 GB), gemma4:latest (9.6 GB) --- quantized GGUF |
| **Python** | 3.9.13 (venv) |

*Reported p50 ≈16 s / p95 ≈70 s latencies reflect CPU-only 7B inference
on an iGPU-only ultrabook --- not an inherent pipeline property.*

# Test Suite Summary

| Suite | Count | Notes |
| :--- | :---: | :--- |
| **Unit tests** | 434 | 22 files. Largest: sub_intent 46, adversarial 42, regex 40, semantic_cache 37, session_context 35, input_normalizer 31, feature_flags 29 |
| **Integration tests** | 48 | test_api 12, test_api_v2 33, test_audit_escalation_api 3 |
| **Total** | 482 | Measured directly from source, 2026-08-26 (regex over def test\_ / async def test\_) |

# Golden Dataset Composition (eval/golden_dataset.jsonl, 900 records)

***Category Distribution***

| Category | Count |
| :--- | :---: |
| well_formed | 400 |
| adversarial_injection | 100 |
| out_of_scope | 90 |
| hallucination_fabricated_cve | 64 |
| hallucination_fabricated_parameter | 64 |
| hallucination_contradictory_action_target | 64 |
| hallucination_target_type_mismatch | 64 |
| ambiguous | 30 |
| rbac_violation | 24 |

***Other Facets***

| Facet | Distribution |
| :--- | :--- |
| **Expected intent** | NETWORK_SCAN 149 · EXPLOITATION 140 · REJECTED 140 · VULNERABILITY_AUDIT 135 · PASSIVE_RECON 77 · SERVICE_ENUMERATION 72 · PASSWORD_ATTACK 72 · DIRECTORY_BRUTEFORCE 68 · AMBIGUOUS 30 |
| **Role** | Admin 260 analyst 540 · operator 60 · viewer 40 |
| **Difficulty** | easy 185 · medium 536 · hard 180 |
| **Expected blocked-reason labels** | prompt_injection 100 · scope_violation 63 · command_out_of_scope 27 · fabricated_cve 64 · type_mismatch 64 · contradictory 64 · fabricated_parameter 64 · rbac_denied 24 · ambiguous 30 |
| **Sub-intent ground truth** | 711/900 records carry a sub_intent; 26 distinct values |
| **CVE-bearing records** | 140 |

*No viewer-role rows exist in the golden dataset --- experiments
exercise only the post-inference RBAC path.*

# Experiment 1 - Raw LLM vs Full Pipeline

Design: 2×2 factorial --- {Raw LLM, Full Pipeline} × {gemma4:latest,
qwen2.5-coder:7b}.

***Overall Comparison***

| Metric | Raw Gemma | Raw Qwen | Pipeline+Gemma | Pipeline+Qwen |
| :--- | :---: | :---: | :---: | :---: |
| **Intent Accuracy** | 78.0% | 69.0% | 86.0% | 82.0% |
| **Hallucination Catch Rate** | 0.0% | 0.0% | 72.0% | 64.0% |
| **False-Positive Rate** | 32.0% | 31.0% | 14.0% | 15.0% |
| **p50 latency (s)** | 11.5 | 13.5 | 27.7 | 32.8 |
| **p95 latency (s)** | 63.3 | 16.5 | 148.3 | 177.7 |
| **p99 latency (s)** | 93.7 | 17.4 | 220.8 | 247.2 |
| **Mean latency (s)** | 25.3 | 13.4 | 39.6 | 45.2 |

*Pipeline vs. raw deltas: accuracy +18pp (Gemma) / +16pp (Qwen); catch
+52pp / +50pp; FP −18pp / −16pp.*

***Per-Intent Accuracy (%)***

| Intent | Raw Gemma % | Raw Qwen % | Pipe Gemma % | Pipe Qwen % |
| :--- | :---: | :---: | :---: | :---: |
| AMBIGUOUS | 0.0 | 0.0 | 83.3 | 83.3 |
| DIRECTORY_BRUTEFORCE | 9.0 | 8.0 | 94.0 | 89.4 |
| EXPLOITATION | 93.0 | 86.0 | 100.0 | 90.9 |
| NETWORK_SCAN | 76.5 | 70.6 | 76.5 | 76.5 |
| PASSIVE_RECON | 54.5 | 54.5 | 90.9 | 90.9 |
| PASSWORD_ATTACK | 100.0 | 100.0 | 100.0 | 100.0 |
| REJECTED | 16.7 | 66.7 | 0.0 | 0.0 |
| SERVICE_ENUMERATION | 76.9 | 69.2 | 92.3 | 92.3 |
| VULNERABILITY_AUDIT | 84.0 | 87.0 | 93.3 | 93.3 |

***Per-Category Decision Accuracy (%)***

| Category | Raw Gemma | Raw Qwen | Pipe Gemma | Pipe Qwen |
| :--- | :---: | :---: | :---: | :---: |
| well_formed | 68.0 | 69.0 | 86.0 | 85.0 |
| adversarial_injection | 0.0 | 0.0 | 100.0 | 100.0 |
| ambiguous | 0.0 | 0.0 | 80.0 | 80.0 |
| hallucination_contradictory_action_target | 0.0 | 0.0 | 16.7 | 16.7 |
| hallucination_fabricated_cve | 0.0 | 0.0 | 33.3 | 33.3 |
| hallucination_fabricated_parameter | 0.0 | 0.0 | 91.7 | 91.7 |
| hallucination_target_type_mismatch | 0.0 | 0.0 | 33.3 | 33.3 |
| out_of_scope | 0.0 | 0.0 | 0.0 | 0.0 |
| rbac_violation | 0.0 | 0.0 | 100.0 | 100.0 |

# Experiment 2 - Model Head-to-Head (Full Pipeline)

Design: gemma4:latest vs qwen2.5-coder:7b, identical 800 records, both
through the full pipeline.

***Overall***

| Metric | Gemma 4 | Qwen 2.5 Coder | Delta |
| :--- | :---: | :---: | :---: |
| Intent Accuracy | 86.0% | 82.0% | −4.0pp |
| Hallucination Catch Rate | 72.0% | 64% | −8.0pp |
| FP Rate | 14.0% (28 FPs) | 15.0% (30 FPs) | +1.0pp |
| p50 (ms) | 27,650 | 32,755 | +5,105 (\~18% slower) |
| p95 (ms) | 148,347 | 177,666 | +29,319 (\~19.8% slower) |
| Mean (ms) | 39,555 | 45,208 | +5,653 (\~14.3% slower) |

***Per-Intent Accuracy***

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

***Per-Category Decision Accuracy (%)***

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

# Experiment 3 - Component Ablation (Canonical Run 8)

Design: 8 configurations × 900 golden records (7200 pipeline runs); one
component removed per configuration.

***Main Results***

| # | Config | Component Removed | DAcc % | Catch % | FP % | CFAcc % | p50 (ms) | p95 (ms) | Mean (ms) |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | Full Pipeline | --- | 73.5 | 84 | 34 | 87.5 | 16,498 | 70,893 | 28,805 |
| 2 | No Scope Guard | ScopeGuard (+Adversarial) | 64.0 | 73 | 44 | 83.9 | 17,355 | 71,296 | 31,404 |
| 3 | No RBAC Guard | RBACGuard | 74.5 | 64 | 22 | 88.2 | 16,788 | 72,548 | 28,260 |
| 4 | No Network Validator | NetworkArchitectureValidator | 68.0 | 82 | 44 | 83.9 | 15,868 | 71,295 | 27,450 |
| 5 | No Hallucination Validator | Schema+RegexValidator | 65.4 | 62 | 44 | 82.1 | 15,915 | 70,547 | 26,722 |
| 6 | Validation Stack Disabled | Entire stack (S5,S6,S6B,S7) | 64.0 | 41 | 13 | 87.4 | 14,291 | 60,631 | 25,198 |
| 7 | Self-Consistency Disabled | Tier-2 sampling | 67.5 | 80 | 45 | 85.5 | 13,388 | 16,846 | 11,809 |
| 8 | Semantic Cache Disabled | SemanticCache middleware | 66.0 | 79 | 47 | 86.8 | 14,372 | 55,731 | 22,949 |

***Waterfall Deltas (vs. previous step)***

| Step | Config | Removed | DAcc Δ | Catch Δ | FP Δ | Mean-lat Δ (ms) |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: |
| 0 | **Full Pipeline** | --- | **0.0** | **0** | **0** | **0** |
| 1 | No Scope Guard | ScopeGuard (+Adversarial) | −9.5 | −11 | +10 | +2,599 |
| 2 | No RBAC Guard | RBACGuard | +1.0 | −20 | −12 | −545 |
| 3 | No Network Validator | NetworkArchitectureValidator | −5.5 | −2 | +10 | −1,355 |
| 4 | No Hallucination Validator | Schema+RegexValidator | −8.1 | −22 | +10 | −2,083 |
| 5 | Validation Stack Disabled | Entire stack (S5,S6,S6B,S7) | −9.5 | −43 | −21 | −3,607 |
| 6 | Self-Consistency Disabled | Tier-2 sampling | −6.0 | −4 | +11 | −16,996 |
| 7 | Semantic Cache Disabled | SemanticCache middleware | −7.5 | −5 | +13 | −5,856 |

***Component Contribution Ranking (removal impact vs. baseline)***

| Rank | Component Removed | Acc Drop (pp) | Catch Drop (pp) | FP Change (pp) | Mean-lat Change (ms) |
| :---: | :--- | :---: | :---: | :---: | :---: |
| 1 | SchemaValidator + RegexValidator | +9.5 | +17.0 | +2.0 | −2,082.6 |
| 2 | ScopeGuard (+AdversarialDetector) | +4.5 | +7.0 | +2.0 | +2,599.0 |
| 3 | Entire Validation Stack | +4.5 | +38.0 | −29.0 | −3,606.7 |
| 4 | Semantic Cache | +2.5 | 0.0 | +5.0 | −5,855.3 |
| 5 | Tier-2 Self-Consistency | +1.0 | −1.0 | +3.0 | −16,995.5 |
| 6 | NetworkArchitectureValidator | +0.5 | −1.0 | +2.0 | −1,354.1 |
| 7 | RBACGuard | −6.0 | +15.0 | −27.0 | −544.9 |

*Ranked by safety impact instead: Validation Stack +38 \> Schema+Regex
+17 \> RBAC +15 \> ScopeGuard +7 \> Cache 0 \>
NetValidator/Self-Consistency −1.*
