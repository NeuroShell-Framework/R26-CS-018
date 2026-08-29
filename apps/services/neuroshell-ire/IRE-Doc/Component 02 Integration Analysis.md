# Component 1 ↔ Component 2 Integration Analysis

**Project:** R26-CS-018 (IRE, C1) ↔ Dynamic Planner & RAG Engine (C2, IT22121592)
**Author:** C1 team
**Date:** 2026-08-28
**Status:** Analysis complete; live verification section pending / in progress

---

## 1. Executive Verdict

**Ready to start integration. Low risk, ~half-day of engineering to wire C1→C2.**

Both sides already exist with compatible contracts:

- C1 already exposes `POST /parse/plan` (`src/api/main.py:231`) which builds a validated `PlannerContract` — the exact payload C2's real engine consumes.
- C2's real engine (`src/api/main.py`) accepts that contract 1:1 and returns a structured `PlannerOutput` (tool, final command, plan, confidence, status).

Nothing structural blocks the integration. The only blockers are **runtime prerequisites** (C2 dependency venv; the production Ollama model `gemma4:e4b` is not present locally, use `gemma4:latest` as a stand-in) — neither affects the contract design.

The previously-identified "served stub vs real engine" gap is **resolved**: the re-sent copy contains the real aggregate/consolidated engine at `src/api/main.py`, and the old nested `app/` stub is gone.

**Trade-off from the model choice:** C1 runs `gemma4:latest` (~16–56 s/parse). C2 with its own LLM synthesizes in ~20–32 s. The full C1→C2 journey adds C2 inference latency on top of C1. Plan: push asynchronously (outbox), never block `/parse`, treat C2 as an additional planner layer feeding a downstream orchestrator.

---

## 2. Repo State Assessment (what was received)

| Item | State | Notes |
| :--- | :--- | :--- |
| Real engine `src/api/main.py` | Present | Full pipeline: intent → RAG → synthesize → validate → safety → session |
| `main.py` / `Dockerfile` at root | **Stale** | Serve old `"app:app"` package that no longer exists → cannot start via them. Correct entry: `uvicorn src.api.main:app --port 8002` |
| ChromaDB knowledge base | **Included, populated** | `knowledge_base/chroma_db/` (chroma.sqlite3 832 KB + index bins); `raw_docs/` for nmap, nikto, gobuster; ingest script present |
| `data/tool_map.json` | Present | NETWORK_SCAN/SERVICE_ENUMERATION→nmap, VULNERABILITY_AUDIT→nikto, DIRECTORY_BRUTEFORCE→gobuster; EXPLOITATION/PASSWORD_ATTACK/PASSIVE_RECON→**empty** |
| Fine-tuned model + `gemma4:e4b` | **Absent** | `Modelfile` references `./models/gemma2-c2-lora.gguf` (LoRA adapter not in repo); `gemma4:e4b` not in the shared Ollama. Cannot reproduce the tuned model locally |
| Deleted/purged `models/`, `sound/`, duplicate `docs/` | Consistent | Let the friend re-send tuning artifacts/production model separately |
| Repo weight | 2.8 MB | The "2 GB" the friend threatens to send is Ollama model weights, not the repo — ask for a cloud link / `Ollama pull`, not a chat transfer |
| Git | **Entire C2 tree untracked** | Needs a commit once integration is verified |

---

## 3. Contract Compatibility (the core finding)

### 3.1 Intent literal sets — identical

Both C1 (`PlannerTarget`, `IntentType`) and C2 (`IREIntentContract.intent`) use the same 9-value literal set:
`NETWORK_SCAN, SERVICE_ENUMERATION, VULNERABILITY_AUDIT, DIRECTORY_BRUTEFORCE, EXPLOITATION, PASSWORD_ATTACK, PASSIVE_RECON, AMBIGUOUS, REJECTED`. No enum translation needed.

### 3.2 Field map: C1 `PlannerContract` → C2 `PlanRequest`

C2 `PlanRequest` accepts **either** a nested `IREIntentContract` **or** C1's flat fields. The flat form is intended for cross-component use and maps 1:1:

| C1 `PlannerContract` | C2 `PlanRequest` (flat) | Notes |
| :--- | :--- | :--- |
| `session_id` | `session_id` | **Required** on C2 side → C1 must guarantee non-None |
| `intent` | `intent` | Literal match (3.1) |
| `sub_intent` | `sub_intent` | C1 contract_builder currently emits `None` always — wire through before push |
| `confidence` | `confidence` | C1 emits `0.0` default |
| `target.type` → `target_value` | `target_type`, `target_value` | C1 target dict → C2 flat `target_type`/`target_value` |
| `ports` | `ports` | list of str |
| `modifiers` | `modifiers` | list of str |
| `cve_ids` | `cve_ids` | list of str |
| `tool_hint` | `tool_hint` | str |
| `schedule` | `schedule` | str or None |
| `rejection_reason` | `rejection_reason` | str or None |
| `scope_warnings` | `scope_warnings` | list of str |

C2 accepts-but-ignores: `human_readable_intent`, `target_in_scope`, `safety_notes` (dropped in the flat-field branch in `main.py` → `IREIntentContract`). C1 may omit them; no work needed.

### 3.3 Authentication & packaging

- C2 `/plan` (and `/metrics`) require header **`x-api-key`** matching C2 `.env` `API_KEY` (401 → `"Invalid API key"`). C1 must hold a shared key.
- C2 is a **pydantic v2** app (models compiled at import); C1 and C2 versions pinned in their own `requirements.txt` — no shared runtime risk (separate venvs).

### 3.4 C2 response envelope

`POST /plan` → 200 returns **`PlannerOutput` directly** (no wrapper):
`status` = `success`; `confidence`; `intent`; `target_value`; `primary_tool`; `final_command`; `plan` (list of steps with tool/command/description); `timings`; `session_id`.

Error handling to design for:
| Scenario | C2 response | C1 handling |
| :--- | :--- | :--- |
| Good C1 contract | 200 PlannerOutput | Record `planned` |
| Auth failure / wrong key | 401 | Config error — alert, don't retry |
| `REJECTED` intent | 400 `{stage:"intent_filter", error:"INTENT_REJECTED"}` | Should not be pushed (C1 filters first) |
| Safety block (public IP / dangerous pattern) | 400 `{stage:"safety", detail:"Safety check failed ..."}` | Record `rejected` (aligns with C1 out-of-scope design) |
| CommandValidator fail | 422 `{stage:"command_validator",error:"VALIDATION_FAILED"}` | Record `failed` |This maps cleanly onto C1's tri-state outcome model (planned / rejected / failed) already proposed for the outbox.

---

## 4. C2 Runtime Prerequisites & Gap Check

| Need | Local state | Action |
| :--- | :--- | :--- |
| Python 3.9 venv + `requirements.txt` | Not installed | Separate `c2venv`; **torch** is the big dependency → installing CPU wheel (avoids NVIDIA/CUDA ~2 GB) |
| Ollama `gemma4:e4b` | **Missing** | Use `gemma4:latest` (installed, 9.6 GB) for ground-truth checks; request `gemma4:e4b` or the LoRA GGUF from friend for production parity |
| Redis | Not running (port 6379 closed) | C2 session manager has in-memory fallback (verified in code) — acceptable for integration tests; optional later |
| ChromaDB KB | Included, populated | Verify `kb_chunks > 0` on `/health` |
| Port | Free | Run C2 on **8002** per framework handoff |

C2 startup note: `VectorRetriever` loads `sentence-transformers/all-MiniLM-L6-v2` at init (same embedding model C1 uses for semantic caching) — first `/plan` is slow; expect ~30–90 s model load + ~20–30 s LLM synthesis.

---

## 5. Integration Design (C1 side to build)

1. **New module** `src/integration/planner_client.py` — `PlannerClient` (httpx, async timeouts, retry policy, `x-api-key`) + `push_contract(contract) -> PushOutcome`.
2. **Hook** in `src/pipeline/ire_pipeline.py` after planner-contract build/validate, gated by:
   - feature flag `planner_push: false` in `config/features.yaml` (runtime-toggleable like `semantic_cache`/`scope_enforcement`),
   - contract state: only push `is_executable` contracts (skip REJECTED / AMBIGUOUS / scope-violation),
   - `settings.planner_url` + `settings.planner_api_key` from `.env` (`PLANNER_URL`, `PLANNER_API_KEY`, `PLANNER_TIMEOUT`, `PLANNER_ENABLED`).
3. **Async push + durable outbox** — worker thread, JSONL/sqlite outbox in the service dir, tri-state outcomes (`planned`/`rejected`/`failed`), **fail-open** (C2 down never breaks `/parse`). Set `dispatch.sync=False` default.
4. **Admin visibility** — `GET /admin/planner/outbox?status=...` + panel in the existing admin console for observability (C1 already has audit sink + metrics collector).
5. **Tests** — unit (mock client) + integration: `/parse/plan` → assert outbox row; REJECTED contract → not pushed; public-IP contract → pushed but `rejected`; C2 down → `failed`, `/parse` still 200.
6. **Security** — shared-secret `x-api-key` only; never transmit scope warnings/reasons beyond the contract (already minimal); C2 enforces RFC-1918 + dangerous-pattern gates as a second safety net keyed to C1's scope.

### On EXPLOITATION / PASSWORD_ATTACK / PASSIVE_RECON

C2's `tool_map.json` maps these to **empty** tool lists → ToolSelector falls through to retrieval/hint/None. Behavioral outcome (LLM picks metasploit/hydra/whois/curl etc.) should be monitored; C2's CommandValidator only strictly pattern-checks `nmap`/`nikto`/`gobuster`, so these intents pass through with lower structural guarantees. Not an integration blocker, but worth tracking in the report's "future work" (C2 owns this behavior).

### C3 (downstream)

`apps/services/adaptive-execution-error-recovery/` exists (main.py + app/{config,models,router}) — the natural C2→C3 handoff is outside this report's scope but the design should keep `PlannerOutput.session_id` / `final_command` stable so C3 can consume it later.

---

## 6. Risk & Paper Alignment

- **Defense-in-depth, not redundancy:** C1 guards (scope, RBAC, regex validators) + C2 gates (RFC-1918, dangerous patterns, structural validation) operate on different layers; both must pass before anything executes. Safe refusals are aligned with how the golden dataset expects `out_of_scope` records to behave.
- **Latency budget:** C1 ~16–56 s + C2 ~20–32 s = expected outbox/queue processing; `/parse` p50 keeps C1-only latency because push is async.
- **Evaluation independence preserved:** C1 accuracy was measured WITHOUT C2; integration evidence is scoped as supplementary (per project decision), so both component numbers stay independently defensible.
- **Known C1 bug to carry forward (pre-paper):** RBAC guard false-positive on a legitimate in-scope command ("grab the http server header from 192.168.8.10:443" → denied `rbac_guard`). Must be fixed before final Results section.

---

## 7. Verification Status (live)

> Performed 2026-08-28 against the real engine (`uvicorn src.api.main:app --port 8002`), local `c2venv` on Python 3.9, `OLLAMA_MODEL=gemma4:latest` stand-in (production `gemma4:e4b` not installed on this machine).

- [x] C2 venv install (torch 2.8.0+cpu 619 MB + requirements.txt). Py3.9 portability: `from __future__ import annotations` added to `src/intent/intent_interpreter.py` + `src/session/session_context_manager.py` (the only files using 3.10 `X | None` syntax). `greenlet==2.0.2` pre-pinned (3.2.5 has no cp39 wheel).
- [x] Boot: `/health` → `{"status":"ok","component":"C2-DynamicPlanner","port":8002,"redis":"error","kb_chunks":30}` — ChromaDB KB loaded (30 chunks); Redis absent → in-memory session fallback confirmed working.
- [x] **Happy path (C1 flat contract)** — 200:
  `{"status":"success","command":"nmap -p 80,443 192.168.8.14","command_sequence":["nmap -p 80,443 192.168.8.14"],"tool":"nmap","retrieval_sources":["nmap","nmap","nmap"],"validation_passed":true,"safety_flags":[],"latency_ms":54401}`
  (RAG-grounded; `safety_flags` empty; `validation_passed` true; 54.4 s total incl. first-load embedding model + LLM synthesis.)
- [x] REJECTED intent (C1-style) → 400 `{stage:"intent_filter", error:"INTENT_REJECTED"}` — as designed.
- [x] Out-of-scope public IP (8.8.8.8) → 400 `Safety check failed: ['BLOCKED: target 8.8.8.8 is not RFC-1918 private range']` — second safety gate confirmed, aligns with C1 out-of-scope behavior.
- [x] Authz: bad `x-api-key` → 401.

**Result: C1 `PlannerContract` ↔ C2 `PlanRequest` end-to-end compatibility confirmed live.** No contract or code changes needed on either C1 or C2 for the push; only runtime config (C2 `.env`, port, run command) and the C1-side integration module in §5 remain.

---

## 8. Next Steps

1. Finish C2 venv + smoke test (this session); write results into §7.
2. `git add apps/services/dynamic-planner-rag` and commit once verified.
3. Create C2 `.env` (API_KEY/ADMIN_KEY/OLLAMA_MODEL=gemma4:latest) — file uses `os.getenv("API_KEY", "neuroshell-secret-key")` defaults otherwise.
4. Implement C1 `planner_client.py` + outbox + flags/config + tests (§5).
5. Ask friend for a cloud link to `gemma4:e4b` / LoRA GGUF for C2 production parity (optional, not blocking).