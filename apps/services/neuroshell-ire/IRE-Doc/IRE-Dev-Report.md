# IRE-Dev-Report

**Component:** NeuroShell IRE (Intent Recognition & Extraction)
**Reference:** R26-CS-018 — Component 01 of the NeuroShell Framework
**Author:** T. Hariprasad (MSc Cybersecurity)
**Repo:** https://github.com/NeuroShell-Framework/neuroshell-core.git
**Branch:** `feature/tharindu`
**Session:** Neuro-shell-PP2
**Date:** 2026-08-15

---

## 1. Project Intro (from the start)

**NeuroShell** is a microservices monorepo for an autonomous penetration testing framework. It is split into several independent services, each owned by a different teammate:

| Service dir | Purpose |
|---|---|
| `neuroshell-ire` | **Intent Recognition & Extraction** — the NLU gateway (this component) |
| `dynamic-planner-rag` | Planning / RAG (teammate) |
| `adaptive-execution-error-recovery` | Execution & error recovery (teammate) |
| `ai-vulnerability-analysis` | Vulnerability analysis (teammate) |
| shared infra (`infra/`, `shared/`, root `tests/`, CI) | Integration glue (team) |

The **research gap** that motivates the project: no existing autonomous pentest framework ships a *dedicated, isolated NLU layer* that reliably converts natural-language offensive security commands into validated, schema-constrained machine contracts. Most tools accept free text or strict CLI args but nothing in between. NeuroShell-ire fills that gap as **Component 01**: a domain-specific NLU service that takes a pentester's plain-English instruction (e.g. *"scan 10.0.0.0/24 for eternalblue"*) and returns a **validated JSON intent contract** the rest of the pipeline (planner → executor → analyzer) can consume.

The component is authored on branch `feature/tharindu` and is currently fully in sync with `origin`.

---

## 2. Component Overview

**Mission:** convert natural-language offensive security commands into a validated, schema-constrained JSON **intent contract** via a 7-stage pipeline, with LLM inference (Ollama/Gemma), strict multi-layer validation, session awareness, RBAC, caching, and explainability.

**Codebase scale (current):**
- ~3,654 lines of source across 24 non-test modules
- **436 test functions** across 16 test files (verified by scan, excluding `.venv`)
- 7 development-support scripts (verification / launcher / LoRA scaffolding)

**Runtime:** FastAPI + Uvicorn on port 8001; `.env` → `OLLAMA_MODEL=gemma4:latest`, `SCOPE_MODE=research`, `LOG_LEVEL=INFO`.

---

## 3. Architecture: The 7-Stage Pipeline

Implemented in `src/pipeline/ire_pipeline.py` (338 lines). An incoming parse request flows through:

1. **Preprocessing** — `input_normalizer.py` (74): trim, unify whitespace/case, strip noise; `alias_resolver.py` (44): map known aliases → CVEs using `data/alias_map.json` (21 lines, 22 alias→CVE entries, e.g. EternalBlue→CVE-2017-0144, Log4Shell→CVE-2021-44228).
2. **Sub-intent classification** — `sub_intent_classifier.py` (260): splits compound commands into a primary intent + secondary intents (e.g. *"scan then exploit"* → primary `scan`, secondary `exploit`).
3. **Inference** — `ollama_inference_engine.py` (157): Ollama client, few-shot system prompt, JSON-mode generation, temperature control, and a response cache.
4. **Schema building** — `intent_schema.py` (393): maps the LLM output onto `IntentSchema`; enums `IntentType`, `TargetType`, etc.
5. **Validation** — `validation/*` (6 modules, 481 lines combined): layered checks (details in §5).
6. **Contract construction** — `contract_builder.py` (238): builds a `PlannerContract` for the planner (used by `/parse/plan`).
7. **Response assembly** — constructs `IREResponseV2` (XAI block, uncertainty band, cache_hit flag, scope warnings) with `X-IRE-Schema-Version` header.

---

## 4. Schema v2 (the contract)

`src/schemas/intent_schema.py` (393) + `planner_contract.py` (181).

- **`IntentType` / `TargetType`** enums constrain recognized actions (scan, exploit, recon, exploit-chain…) and target kinds (host, subnet, range, domain…).
- **`IntentSchema`** — the normalized intent: `intent`, `target`, `parameters` (ports, protocols, payloads…), confidence.
- **`IREResponseV1` / `IREResponseV2`** — V2 adds the research-grade fields:
  - `sub_intent`, `secondary_intents[]`
  - `xai` (explainability: rationale, model, schema_version, latency)
  - `uncertainty_band` (low/medium/high)
  - `cache_hit` (bool) + cache details
  - `rbac_role` (permission context)
  - `session_turns` (conversation state)
  - `scope_warnings[]` (engagements scope guard)
- **`ParseRequestV1` / `ParseRequestV2`** and typed error responses.
- **`PlannerContract`** — the machine-ready handoff artifact for the planner.

---

## 5. Middleware & Guards

`src/middleware/*` (6 modules, ~994 lines):

- **`adversarial_detector.py` (227)** — inspects payloads for prompt injection / jailbreak / metasploit-style embedded commands; blocks or downgrades suspicious input.
- **`session_context.py` (237)** — builds and tracks per-session context (turns, history, identity) for stateful intent resolution.
- **`sub_intent_classifier.py` (260)** — pre-classification of compound commands before inference.
- **`semantic_cache.py` (171)** — semantic + exact LRU cache keyed on normalized intent to avoid redundant LLM calls.
- **`rbac_guard.py` (86)** — pre/post RBAC enforcement against `config/rbac_policy.py` (61).
- `__init__.py` (13) — module wiring.

---

## 6. Validation Stack

`src/validation/*` (6 modules, 481 lines combined):

- **`network_validator.py` (234)** — IP/range/subnet/domain syntax validation, CIDR math, port ranges.
- **`scope_guard.py` (73)** — enforces `SCOPE_MODE` (`research` currently); flags out-of-scope targets as warnings.
- **`regex_validator.py` (70)** — regex safety (reject ReDoS-prone patterns / regex bombs).
- **`json_parser.py` (47)** — strict JSON parsing + graceful LLM-output repair.
- **`schema_validator.py` (26)** — Pydantic conformance.
- **`contract_validator.py` (31)** — **NOTE: dead code** — built but not yet wired into the pipeline or API (see §9 issues).

---

## 7. API Surface

`src/api/main.py` (400 lines) — FastAPI entry, lifespan startup, rate limiting (slowapi, 30/min), API key + RBAC.

| Endpoint | Purpose |
|---|---|
| `POST /parse` | V1 parse → intent |
| `POST /parse/plan` | V2 parse → PlannerContract |
| `GET /metrics` | inference/latency metrics (`metrics_collector.py`, 55) |
| `GET/POST/DELETE /session/*` | session context management |
| `GET/POST /admin/rbac/*` | RBAC policy inspection/update |
| `GET /admin/features` | feature-flag status (`feature_flags.py`, 95 + `features.yaml`) |
| `GET /engagement/scope` | active scope retrieval |

All responses carry `X-IRE-Schema-Version`.

---

## 8. Config, Inference & Ops

- **Config:** `config/settings.py` (78) — pydantic-settings, `.env` driven; `config/feature_flags.py` (95) + `features.yaml`; `config/rbac_policy.py` (61); `config/lora_config.yaml` (Phase-7 scaffold).
- **Inference:** `ollama_inference_engine.py` (157) — Gemma via Ollama, few-shot prompt, structured output, LRU cache, metric logging.
- **Utils:** `logging_config.py` (43) — structlog; `metrics_collector.py` (55).
- **Daemon scripts (added this session, untracked):** `neuroshell_run.ps1/.cmd` (starts uvicorn on 8001, writes `.uvicorn.pid`, logs to `logs/`, `-NoReload`/`-Port` switches) and `neuroshell_stop.ps1/.cmd` (kills PID tree, port fallback). Stop verified (PID 1824 killed, port 8001 freed).
- **Run cmd:** `.venv\Scripts\python.exe -m uvicorn src.api.main:app --port 8001 --reload`
- **Venv:** Python 3.9.13 (README recommends 3.11+); fastapi 0.115.0, uvicorn 0.30.6, pydantic 2.8.2, ollama 0.3.3, slowapi 0.1.9, spacy 3.7.6, structlog 24.4.0, sentence-transformers 3.0.1, pytest 8.3.2.

---

## 9. What Has Been Developed So Far (deliverables)

1. **Full 7-stage intent pipeline** — preprocessing → sub-intent → inference → schema → validation → contract → response.
2. **Schema v2** with sub_intent, secondary_intents, XAI, uncertainty_band, cache_hit, rbac_role, session_turns, scope_warnings.
3. **Complete middleware set** — adversarial detection, RBAC, session context, semantic cache, sub-intent classification.
4. **Six-module validation stack** (network, scope, regex, JSON, schema, contract).
5. **Ollama/Gemma inference engine** with few-shot prompting + cache + metrics.
6. **Full REST API** — parse/parse-plan, metrics, sessions, RBAC admin, feature flags, scope.
7. **436 tests** (verified) across 16 test files — unit (15 files) + integration (`test_api.py` 12, `test_api_v2.py` 30).
8. **7 scripts** — `run_dev.py` (128), `verify_pipeline_v2.py` (147), `verify_api_v2.py` (139), `verify_validation.py` (136), plus LoRA/Phase-7 scaffolds (`train_lora.py`, `clean_dataset.py`, `evaluate_model.py` — 2 lines each, TODO).
9. **Git history** — IRE work committed across ~14 commits (`36eb3bd` fix → `e4c27e0` unite → `1229191` integration → `c87e552` validation → `9e983fe` unit → `1598055` schemas → `d899bf1` preprocessing → `2719ecb` pipeline → `d265bc5` middleware → `378445c` interface → `4b49950` api → scripts → `a9e48df` add config). Pushed to `feature/tharindu`, in sync.

---

## 10. Known Issues / Next Steps (in-scope)

> Status: all items below were fixed in the same session (2026-08-15) and verified — 436 tests pass (394 unit + 42 integration).

- **Stale test claim:** README tree now lists per-file counts (394 unit + 42 integration); `verify_pipeline_v2.py` T11 asserts no failures instead of hard-coded 136.
- **Dead code:** `contract_validator.py` wired into `POST /parse/plan` (returns 422 CONTRACT_VALIDATION_FAILED on invalid contracts).
- **Mutable default arg:** `IREResponse.from_intent_schema` now defaults `scope_warnings=None` and coerces to `[]`.
- **Dependency pin:** `pydantic>=2.9.0,<3.0.0` (aligned with monorepo ^2.9.0); duplicate `httpx` removed.
- **Double rate-limit:** removed global `default_limits`; only per-endpoint 30/min decorators remain.
- **Cache order risk:** inference cache rewritten as `OrderedDict` (move_to_end / popitem) — dict/list drift eliminated.
- **Phase 7 (TODO):** LoRA fine-tuning scaffolding still unimplemented (awaiting dataset generation).
- **Remaining:** venv still has pydantic 2.8.2 installed — reinstall with `pip install -r requirements.txt` to match new pin; end-to-end run → parse → stop cycle still to be confirmed.

---

## 11. Out of Scope (team-owned, not touched)

- Kong routing (`infra/kong/kong.yml`) references a non-existent `intent-recognition` service name.
- Docker dev/prod compose wiring; root `tests/test_intent_recognition.py` staleness; shared `passlib` dependency gap.
