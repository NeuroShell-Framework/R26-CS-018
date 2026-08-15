# AGENT.md — neuroshell-ire

## Project

`neuroshell-ire` is **Component 01 (ref R26-CS-018)** of the NeuroShell autonomous penetration testing framework (repo `https://github.com/NeuroShell-Framework/neuroshell-core.git`, branch `feature/tharindu`).

It is a domain-specific NLU gateway: it converts natural-language offensive security commands into validated, schema-constrained JSON intent contracts via a 7-stage pipeline:

1. Input normalization + alias resolution (e.g. EternalBlue -> CVE-2017-0144)
2. Sub-intent classification (compound commands -> primary + secondary intents)
3. LLM inference (Ollama / Gemma)
4. JSON parsing
5. Schema validation (Pydantic)
6. Regex + network architecture validation
7. Scope check + response assembly

Middleware: adversarial detection, RBAC, session context, semantic cache, sub-intent classifier.

## Scope

- THIS directory only. Other services (`dynamic-planner-rag`, `adaptive-execution-error-recovery`, `ai-vulnerability-analysis`), `shared/`, `infra/`, root `tests/`, and CI are owned by teammates — do not modify them.
- Don't modify `IRE-Doc/IRE-Dev-Report.md` unless asked; it is a session-generated report.

## Commands (run from this directory)

- Start dev server (foreground): `.venv\Scripts\python.exe -m uvicorn src.api.main:app --port 8001 --reload`
- Start daemon: `.\neuroshell_run.ps1` (or `neuroshell_run.cmd`); stop: `.\neuroshell_stop.ps1` (writes `.uvicorn.pid`, logs to `logs\`)
- Run all tests: `.venv\Scripts\python.exe -m pytest -q`
- Unit only: `.venv\Scripts\python.exe -m pytest tests/unit/ -q`
- Integration only: `.venv\Scripts\python.exe -m pytest tests/integration/ -q` (needs Ollama running; live LLM calls make it slow)
- Verify scripts: `.venv\Scripts\python.exe scripts\verify_pipeline_v2.py`

## Conventions

- `src/schemas/` = Pydantic models + exceptions; `src/api/main.py` = FastAPI entry; `src/pipeline/` = orchestration; `src/middleware/` = cross-cutting middleware; `src/validation/` = validation layers; `src/preprocessing/`, `src/inference/`, `src/utils/`.
- Use `List[...]`/`Optional[...]` from `typing`; pydantic v2 (>=2.9.0) style with `Field`, `field_validator`, `model_validator`.
- Use structlog (see `src/utils/logging_config.py`) with `extra={...}` keyword logging.
- Feature flags live in `config/features.yaml` + `config/feature_flags.py`; runtime config in `config/settings.py` (`.env`-driven).
- Tests: pytest; `tests/unit/` (394 tests), `tests/integration/` (42 tests). Integration tests patch `src.api.main.pipeline` or hit the real pipeline.
- Rate limiting: slowapi 30/min per-endpoint (`@limiter.limit` on `/parse`, `/parse/plan`). Do not add a global `default_limits` (double-limits the endpoints).
- Do not add comments to code unless asked.

## Gotchas

- **Spelling:** the directory is `neuroshell-ire` (n-e-u-r-o-s-h-e-l-l). The misspelling `netroshall-ire` must never be used — it has repeatedly re-created a stray directory.
- venv Python is 3.9.13 (README recommends 3.11+). Model: `gemma4:latest` via Ollama on 11434.
- `src/validation/contract_validator.py` is wired into `POST /parse/plan` only (validates `PlannerContract`).
- Inference engine cache is an `OrderedDict` (`src/inference/ollama_inference_engine.py`).

---

## Technical Deep-Dive & Codebase Analysis: neuroshell-ire

### 1. Executive Architecture Overview

`neuroshell-ire` is an autonomous penetration testing NLU gateway designed to bridge natural language operator instructions and machine-executable planning pipelines.

```
                  ┌─────────────────────────────────────────────────────────┐
                  │                 Incoming API Request                    │
                  │              (POST /parse or /parse/plan)               │
                  └──────────────────────────┬──────────────────────────────┘
                                             │
   ┌─────────────────────────────────────────▼─────────────────────────────────────────┐
   │                        MIDDLEWARE & PRE-PROCESSING GUARDS                         │
   │  • AdversarialDetector  → Scans for prompt injection & structural anomalies       │
   │  • RBACGuard (Pre)      → Fast-fails restricted roles (e.g. viewer)               │
   │  • SessionContextStore  → Injects multi-turn session history into prompt          │
   │  • SemanticCache        → Vector similarity (sentence-transformers) lookup       │
   └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                             │ (Cache Miss)
   ┌─────────────────────────────────────────▼─────────────────────────────────────────┐
   │                           7-STAGE PROCESSING PIPELINE                             │
   │  [Stage 1] InputNormalizer   → Unicode NFKC, strip <think>, standardize jargon   │
   │  [Stage 2] AliasResolver     → Maps vulnerability jargon → CVE identifiers        │
   │  [Stage 3] OllamaInference   → Gemma 4 inference via local Ollama API             │
   │  [Stage 4] JSONParser        → Markdown fence stripping & JSON object extraction  │
   │  [Stage 5] SchemaValidator   → Pydantic v2 IntentSchema structural validation     │
   │  [Stage 6] RegexValidator    → IP/CIDR/CVE/port syntax & shell metachar checks    │
   │  [Stage 6B] NetworkValidator → Engagement scope (CIDR) & prefix sanity checks     │
   │  [Stage 7] ScopeGuard        → Prompt injection re-check & RFC-1918 private check │
   └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                             │
   ┌─────────────────────────────────────────▼─────────────────────────────────────────┐
   │                          POST-PROCESSING & HANDOFF                                │
   │  • RBACGuard (Post)      → Fine-grained intent authorization by role             │
   │  • SubIntentClassifier   → Rule-based hierarchical sub-intent classification     │
   │  • ContractBuilder       → Maps IntentSchema → PlannerContract for Component 02   │
   │  • ContractValidator     → Validates confidence & intent parameters on contract   │
   └───────────────────────────────────────────────────────────────────────────────────┘
```

### 2. Validation Stack (`src/validation/`)

The validation stack acts as a zero-trust multi-layered safety barrier:

1. **`json_parser.py`** (`JSONParser`):
   - Strips Gemma reasoning tags (`<think>...</think>`, `<|think|>`) and markdown fences (` ```json `).
   - Locates string object boundaries (`{...}`) and parses native JSON dictionaries.
   - Raises `JSONParseError` on empty output or syntax failure.

2. **`schema_validator.py`** (`SchemaValidator`):
   - Validates JSON dictionaries against `IntentSchema` using Pydantic v2.
   - Enforces field bounds: `ports` (1-65535), `cve_ids` (`CVE-YYYY-NNNNN`), and `confidence` ($0.0 \le c \le 1.0$).
   - Validates conditional logic: `REJECTED` requires `rejection_reason`; `AMBIGUOUS` requires `confidence` $< 0.5$. Raises `SchemaValidationError`.

3. **`regex_validator.py`** (`RegexValidator`):
   - Verifies target structures using exact regex patterns (`IPV4_RE`, `CIDR_RE`, `IPV6_RE`, `DOMAIN_RE`, `CVE_RE`, `URL_RE`).
   - Prevents command injection by detecting shell metacharacters (`;&|$\\`!><`) inside target strings or modifiers. Raises `RegexValidationError`.

4. **`network_validator.py`** (`NetworkArchitectureValidator`):
   - Enforces scope containment against configured engagement subnets (e.g., `192.168.0.0/16`).
   - Detects target type mismatches (e.g., IP targets containing CIDR `/` or SUBNET targets missing prefix).
   - Enforces CIDR sanity bounds (`max_cidr_prefix`, `/32` single host checks, IPv6 minimum prefix `/64`).
   - Handles modes: `strict` (raises `NetworkValidationError`), `warn` (appends `SCOPE_VIOLATION`/`ARCH_WARNING` message), or `disabled`.

5. **`scope_guard.py`** (`ScopeGuard`):
   - Re-scans input for prompt injection phrases (`ignore previous instructions`, `dan mode`, `jailbreak`).
   - Checks for RFC-1918 private network compliance in `research` mode. Raises `ScopeError` on prompt injection.

6. **`contract_validator.py`** (`ContractValidator`):
   - Validates constructed `PlannerContract` objects (confidence range, non-null intent) during `/parse/plan` requests.

### 3. Pipeline & Middleware Architecture

* **Middleware Stack (`src/middleware/`)**:
  - `AdversarialDetector`: Evaluates input threat scores using lexical injection patterns, structural anomaly checks (base64, script tags, control tokens), and character density metrics.
  - `RBACGuard`: Enforces role-based permissions (`viewer`, `analyst`, `operator`, `admin`) pre- and post-inference.
  - `SessionContextStore`: Maintains multi-turn context per `session_id`, prepending past turn summaries to user commands.
  - `SemanticCache`: Vector similarity lookup (`all-MiniLM-L6-v2`) caching parsed intent responses for highly similar instructions ($\ge 0.97$).
  - `SubIntentClassifier`: Classifies primary intents into sub-intents (e.g., `NETWORK_SCAN.SYN_STEALTH`, `EXPLOITATION.REMOTE_CODE_EXEC`, `SERVICE_ENUMERATION.SMB`).

* **Preprocessing & Inference (`src/preprocessing/`, `src/inference/`)**:
  - `InputNormalizer`: Normalizes Unicode NFKC, strips control tokens, and standardizes pentest jargon (`syn scan` $\rightarrow$ `SYN stealth scan`, `privesc` $\rightarrow$ `privilege escalation`).
  - `AliasResolver`: Maps vulnerability aliases to canonical CVE IDs via `data/alias_map.json` (e.g., `EternalBlue` $\rightarrow$ `CVE-2017-0144`).
  - `OllamaInferenceEngine`: Interfaces with local Ollama (`gemma4:e4b`) using structured system prompts and few-shot examples.

### 4. REST API Surface (`src/api/main.py`)

- `POST /parse`: Primary parse endpoint. Accepts `ParseRequestV2`, returning `IREResponseV2` (or V1 schema depending on `X-IRE-Schema-Version`). Rate-limited to 30 req/min.
- `POST /parse/plan`: Hand-off endpoint producing a validated `PlannerContract` for Component 02.
- `GET /health`: Diagnostic status of Ollama, pipeline, and cache memory.
- `GET /metrics`: Latency metrics (p50/p95/p99) and request distribution.
- `GET/DELETE /session/{session_id}`: Manage multi-turn session contexts.
- `GET/POST /admin/features`: Feature flag inspection and hot-reloading (`config/features.yaml`).
- `GET /engagement/scope`: Active engagement target scope configuration.

### 5. Verification & Test Suite

The codebase maintains **436 automated tests** (394 unit + 42 integration) across 16 test files. All unit and integration tests pass with 100% success.