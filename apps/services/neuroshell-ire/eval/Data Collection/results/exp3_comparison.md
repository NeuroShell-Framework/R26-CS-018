# Experiment 3: Component Contribution (Ablation Study)

**Dataset:** eval/golden_dataset.jsonl — 900 golden records
**Design:** 8 configurations × 900 golden records (7200 pipeline runs); one component removed per configuration — Canonical Run 8
**Source:** IRE-Doc/NeuroShell_IRE_Test_New_Results.md (§ Experiment 3)

## Purpose
Quantify each pipeline component's contribution by disabling one layer at a time and measuring the impact on decision accuracy, flawed-input catch rate, false-positive rate, contract field accuracy, and latency.

## Main Results

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

## Waterfall Deltas (vs. baseline)

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

## Component Contribution Ranking (removal impact vs. baseline)

*Recomputed from the new 900-record main results table (baseline: 73.5 DAcc / 84 Catch / 34 FP / 28,805 ms). The source doc's ranking table carried over the previous run's values and did not match its own main table.*

| Rank | Component Removed | Acc Drop (pp) | Catch Drop (pp) | FP Change (pp) | Mean-lat Change (ms) |
| :---: | :--- | :---: | :---: | :---: | :---: |
| 1 | ScopeGuard (+AdversarialDetector) | +9.5 | +11 | −10 | +2,599 |
| 2 | Entire Validation Stack | +9.5 | +43 | +21 | −3,607 |
| 3 | SchemaValidator + RegexValidator | +8.1 | +22 | −10 | −2,083 |
| 4 | Semantic Cache | +7.5 | +5 | −13 | −5,856 |
| 5 | Tier-2 Self-Consistency | +6.0 | +4 | −11 | −16,996 |
| 6 | NetworkArchitectureValidator | +5.5 | +2 | −10 | −1,355 |
| 7 | RBACGuard | −1.0 | +20 | +12 | −545 |

*Ranked by safety impact instead: Validation Stack +43 > Schema+Regex +22 > RBAC +20 > ScopeGuard +11 > Cache +5 > Tier-2 +4 > NetValidator +2.*

---

## Key Findings

1. **Baseline decision accuracy is 73.5%** with 84% flawed-input catch rate and 34% false positives on the 900-record set.
2. **Validation stack is the single largest safety component**: disabling it costs −43pp catch rate (84 → 41) and −9.5pp DAcc while FPs drop to 13%.
3. **ScopeGuard is the highest-value single validator**: removing it costs the most DAcc (−9.5pp).
4. **RBAC removal improves DAcc but hurts safety**: DAcc rises to 74.5% while catch drops to 64% — RBAC correctly blocks requests, trading throughput for enforcement.
5. **Self-consistency (Tier-2) is pure latency safety-net**: removing it cuts mean latency by −16,996 ms (largest single latency saving) while costing −6.0pp DAcc.
6. **Semantic cache removal** slightly reduces latency capture (+13 FPs to 47%) — it mostly protects against repeat false positives.