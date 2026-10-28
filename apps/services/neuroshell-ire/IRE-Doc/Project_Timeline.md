# Project Timeline

**NeuroShell Core Framework (R26-CS-018) — MSc Cybersecurity Research Project**

This document is the weekly project timeline for the NeuroShell Core Framework, covering all four components as a single system:

- **Component 01 — Intent Recognition Engine (IRE):** NLU gateway converting natural-language operator commands into validated JSON intent contracts.
- **Component 02 — Dynamic Planner RAG Engine:** Retrieval-Augmented Generation planner producing ordered execution graphs and success probabilities.
- **Component 03 — Adaptive Execution and Error Recovery Engine (AEERE):** Self-healing runtime engine categorizing errors and executing recovery strategies.
- **Component 04 — AI Vulnerability Analysis Engine (AVAE):** Scans, parses, enriches (NVD / CISA KEV / FIRST EPSS), predicts exploitability (XGBoost + SHAP) and triages vulnerability findings.

| Field | Value |
|---|---|
| **Document ID** | NS-PROJ-TIMELINE-001 |
| **Version** | 1.0 |
| **Date** | 2026-09-05 |
| **Project** | NeuroShell Core Framework — R26-CS-018 |
| **Start Date** | 2026-03-15 (Proposal Submission) |
| **End Date** | 2026-12-01 (Research Paper Publication Evidence Submission) |
| **Scope** | All 4 components (IRE, Planner, AEERE, AVAE) |
| **Purpose** | Weekly plan for import into Microsoft Teams Planner |

---

# 1. Master Milestone Timeline

The following common timeline applies to the 2026 Regular Batch research project (RP):

| Action | Deadline |
|---|---|
| Proposal Submission | 15th March 2026 |
| Proposal Presentation | 16th to 18th March 2026 |
| Check List submission | 13th May 2026 |
| Progress Presentation 1 | 11th to 13th May 2026 |
| Progress Presentation 2 | 31st August to 02nd September 2026 |
| Draft Thesis submission | 11th October 2026 |
| Website Submission | 11th October 2026 |
| Final Check List submission | 14th October 2026 |
| Final Presentation and Viva | 19th to 21st October 2026 |
| Website evaluation and Logbook submission | 19th to 21st October 2026 |
| Research Paper submission | 23rd October 2026 |
| Final Thesis Submission | 28th October 2026 |
| Research Paper publication evidence submission | 1st December 2026 |

# 2. Weekly Activity Plan

Weekly granularity is used across the entire project. Weeks are Monday-to-Sunday ranges. Work from **2026-03-15 to 2026-09-05** is already completed and is captured retrospectively; work from **2026-09-06 to 2026-12-01** is scheduled. Component tags used: C1=IRE, C2=Planner, C3=AEERE, C4=AVAE, ALL=whole framework.

## 2.1 Week of Proposal Submission (Kickoff)

| Week | Date Range | Milestones and Deliverables |
|---|---|---|
| W00 | 2026-03-15 to 2026-03-15 | **Proposal Submission** (15 Mar). Submit final project proposal; define scope, objectives, 4-component architecture; create MS Teams channel and Planner board. **Comp: ALL — Completed** |

## 2.2 Phase A — Proposal and Foundations (Clients C1-C4)

| Week | Date Range | Milestones and Deliverables |
|---|---|---|
| W01 | 2026-03-16 to 2026-03-22 | **Proposal Presentation** (16-18 Mar). Present proposal to review board; incorporate feedback; refine research questions. **Comp: ALL — Completed** |
| W02 | 2026-03-23 to 2026-03-29 | Literature review: LLM security agents, prompt injection defenses, RAG, CVSS/EPSS/KEV; collect IEEE / OWASP / MITRE references. **Comp: ALL — Completed** |
| W03 | 2026-03-30 to 2026-04-05 | Monorepo scaffolding: apps / shared / infra structure, FastAPI + Poetry environments, docker-compose baseline, git workflow, CI skeleton. **Comp: ALL — Completed** |
| W04 | 2026-04-06 to 2026-04-12 | Kong API Gateway baseline: declarative routing, rate limiting (60 req/min), CORS policy, header injection (X-Gateway-Version, X-Service-Name). **Comp: ALL — Completed** |
| W05 | 2026-04-13 to 2026-04-19 | IRE Stages 1-2: input normalizer (NFKC, whitespace, slang standardization) and alias resolver with data/alias_map.json (EternalBlue, Log4Shell, etc.). **Comp: C1 — Completed** |
| W06 | 2026-04-20 to 2026-04-26 | IRE Stage 3: Ollama integration (gemma4:e4b), prompt engineering, strict JSON generation, thinking-tag and markdown stripping. **Comp: C1 — Completed** |
| W07 | 2026-04-27 to 2026-05-03 | IRE Stages 4-7: JSON extraction, Pydantic IntentSchema validation, regex validation (IP/CIDR/CVE), ScopeGuard (RFC-1918 + prompt injection rejection). **Comp: C1 — Completed** |
| W08 | 2026-05-04 to 2026-05-10 | Progress Presentation 1 preparation: demo of IRE /parse through Kong, slides, draft of first check list. **Comp: ALL — Completed** |

## 2.3 Phase B — Progress Presentation 1 and Implementation

| Week | Date Range | Milestones and Deliverables |
|---|---|---|
| W09 | 2026-05-11 to 2026-05-17 | **Check List submission (13 May); Progress Presentation 1 (11-13 May).** Present IRE pipeline; submit first check list. **Comp: ALL — Completed** |
| W10 | 2026-05-18 to 2026-05-24 | Planner RAG design: PlanStep / GeneratedPlan schemas, vector store selection, RAG context ingestion. **Comp: C2 — Completed** |
| W11 | 2026-05-25 to 2026-05-31 | Planner RAG build: context retrieval, query construction, tool selection, command synthesis, safety filter and command validation. **Comp: C2 — Completed** |
| W12 | 2026-06-01 to 2026-06-07 | AEERE design: error taxonomy (timeout, resource, validation, authentication, network), recovery strategy selection (retry, fallback, circuit breaker). **Comp: C3 — Completed** |
| W13 | 2026-06-08 to 2026-06-14 | AEERE build: RecoveryPlan model, /process-error endpoint, execution latency and outcome tracking. **Comp: C3 — Completed** |
| W14 | 2026-06-15 to 2026-06-21 | AVAE scanner parsing: Nmap, Nikto, Gobuster and generic parsers; ParserRegistry dispatch; EntityCollection output. **Comp: C4 — Completed** |
| W15 | 2026-06-22 to 2026-06-28 | AVAE threat intelligence: NVD client, CISA KEV feed load, FIRST EPSS batch client, SQLite CVE cache. **Comp: C4 — Completed** |
| W16 | 2026-06-29 to 2026-07-05 | AVAE data pipeline: CCEE dataset ingestion, 12-feature engineering, build/merge/train/test CLI scripts. **Comp: C4 — Completed** |
| W17 | 2026-07-06 to 2026-07-12 | AVAE ML model: XGBoost training (grid search, 5-feature runtime contract), SHAP explanations, model artifact and training medians. **Comp: C4 — Completed** |
| W18 | 2026-07-13 to 2026-07-19 | AVAE triage and graph: TriageEngine (filter/dedupe/rank/FP-reduction), service-risk heuristic fallback, Neo4j graph persistence. **Comp: C4 — Completed** |
| W19 | 2026-07-20 to 2026-07-26 | End-to-end integration: C1 to C2 to C3 to C4 chain wiring, shared JWT / Pydantic schemas, VulnerabilityClient and IRE execution orchestration. **Comp: ALL — Completed** |
| W20 | 2026-07-27 to 2026-08-02 | IRE empirical evaluation design: 900-record campaign, metrics harness (intent accuracy, JSON validity, false-positive scope violations). **Comp: C1 — Completed** |
| W21 | 2026-08-03 to 2026-08-09 | Evaluation execution: run campaign, collect results, analyse failure modes, fix discovered defects. **Comp: ALL — Completed** |
| W22 | 2026-08-10 to 2026-08-16 | Hardening: adversarial prompt-injection defenses, hallucination detection, RBAC review, rate-limit verification. **Comp: C1 — Completed** |
| W23 | 2026-08-17 to 2026-08-23 | AVAE verification: parser and ML scoring unit suites (52 tests), false-positive reduction metrics, model metric refinement. **Comp: C4 — Completed** |
| W24 | 2026-08-24 to 2026-08-30 | Progress Presentation 2 preparation: cross-service integration test suite, prod docker-compose resource limits, QA and performance profiling. **Comp: ALL — Completed** |

## 2.4 Phase C — Progress Presentation 2 and Documentation

| Week | Date Range | Milestones and Deliverables |
|---|---|---|
| W25 | 2026-08-31 to 2026-09-06 | **Progress Presentation 2 (31 Aug - 02 Sep).** Present all 4 components; finalize per-component SRS and combined system SRS (markdown, LaTeX, PDF) through **2026-09-05**. **Comp: ALL — Completed** |
| W26 | 2026-09-07 to 2026-09-13 | Address PP2 feedback; finalize project timeline in MS Teams Planner; thesis outline and chapter map. **Comp: ALL — Upcoming** |

## 2.5 Phase D — Thesis Drafting and Website

| Week | Date Range | Milestones and Deliverables |
|---|---|---|
| W27 | 2026-09-14 to 2026-09-20 | Thesis chapters 1-2: introduction, literature review; component documentation and data collection write-up. **Comp: ALL — Upcoming** |
| W28 | 2026-09-21 to 2026-09-27 | Thesis chapters 3-4: system design and implementation per component; architecture figures and tables. **Comp: ALL — Upcoming** |
| W29 | 2026-09-28 to 2026-10-04 | Thesis chapter 5: evaluation results and discussion; website content assembly and screenshots. **Comp: ALL — Upcoming** |
| W30 | 2026-10-05 to 2026-10-11 | **Draft Thesis submission (11 Oct); Website Submission (11 Oct).** Finalize draft thesis and submit website. **Comp: ALL — Due 2026-10-11** |

## 2.6 Phase E — Final Deliverables and Viva

| Week | Date Range | Milestones and Deliverables |
|---|---|---|
| W31 | 2026-10-12 to 2026-10-18 | **Final Check List submission (14 Oct).** Complete final check list, logbook finalization, viva preparation. **Comp: ALL — Due 2026-10-14** |
| W32 | 2026-10-19 to 2026-10-25 | **Final Presentation and Viva (19-21 Oct); Website evaluation and Logbook submission (19-21 Oct); Research Paper submission (23 Oct).** Deliver viva, submit logbook and research paper. **Comp: ALL — Due 2026-10-23** |
| W33 | 2026-10-26 to 2026-11-01 | **Final Thesis Submission (28 Oct).** Incorporate viva feedback, finalize and submit thesis. **Comp: ALL — Due 2026-10-28** |

## 2.7 Phase F — Research Paper Publication

| Week | Date Range | Milestones and Deliverables |
|---|---|---|
| W34 | 2026-11-02 to 2026-11-08 | Paper revision: incorporate reviewer / supervisor feedback, prepare camera-ready version. **Comp: ALL — Upcoming** |
| W35 | 2026-11-09 to 2026-11-15 | Publication follow-up: submit camera-ready, track acceptance and DOI assignment. **Comp: ALL — Upcoming** |
| W36 | 2026-11-16 to 2026-11-22 | Publication evidence compilation: acceptance letter, DOI / published version, repository links. **Comp: ALL — Upcoming** |
| W37 | 2026-11-23 to 2026-11-29 | Evidence package review: QA publication evidence bundle, align with supervisor. **Comp: ALL — Upcoming** |
| W38 | 2026-11-30 to 2026-12-06 | **Research Paper publication evidence submission (01 Dec).** Submit evidence to faculty. **Comp: ALL — Due 2026-12-01** |

# 3. MS Teams Planner Usage

The companion file `MS_Teams_Planner_Import.csv` contains one row per weekly task plus the milestone tasks, ready for import into Microsoft Teams Planner. Columns are: Task Name, Bucket Name, Start Date, Due Date, Progress, Priority, Notes.

- **Buckets** group the plan into Proposal, Phase A Foundations, Phase B Implementation, Phase C Progress 2 and Docs, Phase D Thesis and Website, Phase E Final and Viva, Phase F Publication.
- **Progress** uses Completed (2026-03-15 to 2026-09-05) and Not started (2026-09-06 onwards); switch each task to In progress / Done as work is completed each week.
- **Assignees** can be added in Planner per component owner (C1: IRE, C2: Planner, C3: AEERE, C4: AVAE).