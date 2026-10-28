# 14 — TODO Checklist

> **Component:** C2 — Dynamic Planner & RAG Engine  
> **Verification Status:** All Phase 1–4 steps verified against source code | Phase 5–6 steps tracked as planned items

---

## Checklist Legend

- `[x]` **Verified & Implemented** (Code exists and has been empirically validated against project files)
- `[ ]` **Planned / Future Work** (Reserved schema, directory, or roadmap item for future releases)

---

## 1. API & Gateway Layer (`src/api/main.py`)

- [x] Implement FastAPI application initialization with title, description, and version `1.0.0` (`src/api/main.py:L26-L30`)
- [x] Implement `GET /health` endpoint reporting Redis ping status and ChromaDB chunk count (`src/api/main.py:L45-L61`)
- [x] Implement `POST /plan` endpoint accepting `PlanRequest` and returning `PlannerOutput` (`src/api/main.py:L64-L185`)
- [x] Implement API key authentication header validation (`x-api-key == API_KEY`) (`src/api/main.py:L66-L67`)
- [x] Implement early `REJECTED` intent guard raising `HTTPException(400)` before RAG or LLM processing (`src/api/main.py:L94-L108`)
- [x] Implement dual input format handling (enriched C1 v2 format vs legacy C1 v1 `intent_contract`) (`src/api/main.py:L72-L91`)
- [x] Implement target reinforcement rule appending to prompt (`src/api/main.py:L136-L140`)
- [x] Implement `GET /tools/available` endpoint listing supported tools (`["nmap", "nikto", "gobuster"]`) (`src/api/main.py:L187-L192`)
- [x] Implement `GET /metrics` endpoint returning aggregated performance stats (`src/api/main.py:L195-L199`)
- [x] Implement administrative endpoints validating against `ADMIN_KEY` (`src/api/main.py:L204-L279`)
- [x] Implement dynamic knowledge base update endpoint (`/kb/update`) consuming `KBUpdateRequest` (`src/api/main.py:L211-L227`)

---

## 2. Schema & Data Models (`src/schemas/models.py`)

- [x] Define `ToolParameters` Pydantic model (`flags`, `ports`, `wordlist`, `suggested_command`) (`src/schemas/models.py:L5-L10`)
- [x] Define `IREIntentContract` model supporting all 9 intent literals (`NETWORK_SCAN`, `VULNERABILITY_AUDIT`, etc.) (`src/schemas/models.py:L13-L39`)
- [x] Define `PlanRequest` model supporting nested and flat input schemas (`src/schemas/models.py:L41-L73`)
- [x] Define `PlannerOutput` model returning command, tool, sources, latency, safety flags, and validation status (`src/schemas/models.py:L75-L87`)
- [x] Define `ErrorResponse` model for structured error responses (`src/schemas/models.py:L89-L95`)
- [x] Define `KBUpdateRequest` schema for knowledge base content updates (`src/schemas/models.py:L97-L99`)

---

## 3. Intent Processing Subsystem (`src/intent/`)

- [x] Implement `IntentInterpreter.interpret()` parameter normalization (`src/intent/intent_interpreter.py:L8-L86`)
- [x] Implement port resolution chain (`tool_parameters.ports` $\rightarrow$ `contract.ports` $\rightarrow$ `_default_ports()`) (`src/intent/intent_interpreter.py:L28-L43`)
- [x] Implement tool hint resolution (`primary_tool` $\rightarrow$ `tool_hint`) (`src/intent/intent_interpreter.py:L59-L60`)
- [x] Implement `multi_step` calculation (`intent in MULTI_STEP_INTENTS and confidence > 0.85`) (`src/intent/intent_interpreter.py:L82-L85`)
- [x] Implement `QueryConstructor.build_query()` mapping intents to query templates (`src/intent/query_constructor.py:L30-L57`)
- [x] Implement `MODIFIER_TEXT_MAP` semantic expansion for modifiers (`stealth`, `ssl`, `evasion`, etc.) (`src/intent/query_constructor.py:L1-L17`)
- [x] Implement regex whitespace normalization on constructed queries (`src/intent/query_constructor.py:L54-L55`)
- [x] Consume `suggested_command` in prompt generation as reference hint when provided (`src/rag/context_assembler.py:L23-L34`)
- [x] Implement multi-command sequence synthesis and dual-layer per-command validation on `multi_step == True` (`src/api/main.py:L150-L199`, `src/synthesis/command_synthesizer.py:L20-L59`)

---

## 4. Knowledge Base & RAG Subsystem (`src/rag/`, `scripts/ingest_docs.py`)

- [x] Maintain raw text documentation for supported tools in `knowledge_base/raw_docs/*.txt` (`nmap.txt`, `nikto.txt`, `gobuster.txt`)
- [x] Implement text chunking algorithm (`80` words per chunk, `20`-word overlap) (`scripts/ingest_docs.py:L16-L24`)
- [x] Implement embedding ingestion using `sentence-transformers/all-MiniLM-L6-v2` (`scripts/ingest_docs.py:L30`)
- [x] Implement ChromaDB collection creation with cosine similarity metadata (`scripts/ingest_docs.py:L31-L34`)
- [x] Implement `VectorRetriever` persistent client initialization (`src/rag/vector_retriever.py:L15-L22`)
- [x] Implement tool-filtered vector query execution (`where={"tool": tool_hint}`) (`src/rag/vector_retriever.py:L24-L44`)
- [x] Implement `ContextAssembler.assemble()` for tool-section prompt formatting (`src/rag/context_assembler.py:L5-L41`)
- [x] Implement distance/score threshold filtering (`0.30` default) for retrieved chunks (`src/rag/vector_retriever.py:L24-L44`)
- [ ] Implement document pre-processing pipeline writing to `knowledge_base/processed/` (*Planned*)

---

## 5. Synthesis & Tool Selection Subsystem (`src/synthesis/`)

- [x] Implement `ToolSelector.select()` priority resolution chain (`C1 hint` $\rightarrow$ `RAG source` $\rightarrow$ `tool_map.json`) (`src/synthesis/tool_selector.py:L20-L36`)
- [x] Maintain `data/tool_map.json` mapping intent codes to default tools (`data/tool_map.json:L1-L9`)
- [x] Implement `CommandSynthesizer.synthesize()` calling local Ollama LLM runtime (`src/synthesis/command_synthesizer.py:L20-L59`)
- [x] Support model selection via `OLLAMA_MODEL` environment variable (default: `gemma4:e4b`) (`src/synthesis/command_synthesizer.py:L8`)
- [x] Implement markdown code-fence post-processing (`.replace("```bash", "").replace("```", "")`) (`src/synthesis/command_synthesizer.py:L52-L53`)
- [x] Train and integrate fine-tuned LoRA adapter weights (`models/planner-lora-adapter/`) deployed in Ollama as `neuroshell-c2-gemma2:latest`
- [x] Generate synthetic training and evaluation dataset in `data/synthesis_dataset/`

---

## 6. Dual-Layer Safety & Validation Engine (`src/validation/`)

- [x] Implement `SafetyFilter.validate()` pre-execution validation (`src/validation/safety_filter.py:L33-L49`)
- [x] Implement regex pattern matcher for dangerous shell commands (`rm -rf`, `mkfs`, `dd`, fork bomb, reverse shell, etc.) (`src/validation/safety_filter.py:L4-L15`)
- [x] Implement RFC-1918 private IPv4 target scope restriction (`192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`, `127.x.x.x`, `localhost`) (`src/validation/safety_filter.py:L17-L23`)
- [x] Implement approved tool list validator (`nmap`, `nikto`, `gobuster`, `hydra`, `metasploit`, etc.) (`src/validation/safety_filter.py:L25-L29`)
- [x] Implement `CommandValidator.validate()` structural command verification (`src/validation/command_validator.py:L18-L45`)
- [x] Implement regex tool binary start pattern checking (`^nmap\s+`, `^nikto\s+`, `^gobuster\s+(dir|dns|vhost|fuzz)\s+`) (`src/validation/command_validator.py:L10-L14`)
- [x] Implement mandatory flag verification per tool (`TOOL_REQUIRED_FLAGS`) (`src/validation/command_validator.py:L4-L8`)
- [x] Implement single-line non-empty command validation (`src/validation/command_validator.py:L22-L28`)
- [x] Enforce strict `CommandValidator` rejection raising `HTTPException(422)` when structural validation fails (`src/api/main.py:L157-L168`)

---

## 7. Session Management Subsystem (`src/session/`)

- [x] Implement `SessionContextManager` Redis client initialization (`src/session/session_context_manager.py:L14-L16`)
- [x] Implement `get_session()` fetching JSON state or initializing new default session (`src/session/session_context_manager.py:L18-L29`)
- [x] Implement `update_session()` appending commands, tools, and targets with sliding 1-hour TTL (`3600s`) (`src/session/session_context_manager.py:L31-L48`)
- [x] Implement `clear_session()` key deletion helper (`src/session/session_context_manager.py:L50-L51`)
- [x] Support Redis connection string customization via `REDIS_URL` (`src/session/session_context_manager.py:L9`)
- [x] Implement Redis graceful degradation and connection error fallback with memory store in `SessionContextManager` (`src/session/session_context_manager.py:L22-L66`)
- [x] Implement session target recovery (`get_last_target`) and context injection into synthesis prompt (`src/session/session_context_manager.py:L38-L42`, `src/api/main.py:L114-L119`)

---

## 8. Observability & Metrics Subsystem (`src/utils/`)

- [x] Implement `MetricsCollector` in-memory metrics store (`src/utils/metrics_collector.py:L6-L8`)
- [x] Implement `start_timer()` returning timestamp float (`src/utils/metrics_collector.py:L9-L10`)
- [x] Implement `record()` capturing timestamp, session_id, intent, tool, latency_ms, success, and safety_flags (`src/utils/metrics_collector.py:L12-L28`)
- [x] Implement `get_summary()` returning total, successful, failed counts, and average latency (`src/utils/metrics_collector.py:L30-L43`)
- [ ] Implement persistent metrics backend (Prometheus exporter or Redis persistence) (*Planned*)

---

- [x] Implement tokenized CLI AST Evaluator in `scripts/cli_ast_validator.py` directly addressing PP1 panel feedback
- [x] Construct 25-case reproducible evaluation benchmark in `data/benchmark_eval.json` with dataset provenance
- [x] Upgrade `scripts/evaluate_component.py` with FastAPI TestClient and AST semantic metrics (84.0% Semantic Command Accuracy)
- [x] Implement RAG Ablation Experiment harness in `scripts/experiment_rag_ablation.py` (proving +28.00% RAG accuracy gain)
- [x] Create formal Research Evaluation Report in [`docs/15_evaluation_report.md`](file:///E:/neuroshell-planner/docs/15_evaluation_report.md) with empirical metric tables
- [x] Implement end-to-end evaluation script `scripts/evaluate_component.py`
- [x] Define test case for `NETWORK_SCAN` (Nmap stealth scan) (`scripts/evaluate_component.py:L7-L26`)
- [x] Define test case for `VULNERABILITY_AUDIT` (Nikto SSL scan) (`scripts/evaluate_component.py:L27-L46`)
- [x] Define test case for `DIRECTORY_BRUTEFORCE` (Gobuster dir scan) (`scripts/evaluate_component.py:L47-L66`)
- [x] Define test case for Public IP safety block (`8.8.8.8` block) (`scripts/evaluate_component.py:L67-L86`)
- [x] Implement accuracy reporting and success verification (`scripts/evaluate_component.py:L89-L149`)
- [x] Implement administrative unit tests in `test_admin.py` for `ADMIN_KEY` authentication, `/kb/update`, metrics reset, and session clear (`tests/unit/test_admin.py:L1-L56`)
- [x] Implement comprehensive test suite (51 / 51 tests passing across `tests/unit/` and `tests/integration/`)

---

## 10. Documentation & Compliance (`docs/`)

- [x] Create master documentation index [`docs/README.md`](file:///E:/neuroshell-planner/docs/README.md)
- [x] Create [`docs/01_system_overview.md`](file:///E:/neuroshell-planner/docs/01_system_overview.md) with system architecture and Proposal vs Implementation section
- [x] Create [`docs/02_api_reference.md`](file:///E:/neuroshell-planner/docs/02_api_reference.md) with exact request/response schemas and endpoints
- [x] Create [`docs/03_data_models.md`](file:///E:/neuroshell-planner/docs/03_data_models.md) with Pydantic class descriptions
- [x] Create [`docs/04_pipeline_flow.md`](file:///E:/neuroshell-planner/docs/04_pipeline_flow.md) with 9-step request flow diagram
- [x] Create [`docs/05_module_reference.md`](file:///E:/neuroshell-planner/docs/05_module_reference.md) detailing class and method signatures
- [x] Create [`docs/06_rag_subsystem.md`](file:///E:/neuroshell-planner/docs/06_rag_subsystem.md) documenting ingestion and vector search
- [x] Create [`docs/07_safety_validation.md`](file:///E:/neuroshell-planner/docs/07_safety_validation.md) covering dangerous patterns and RFC-1918 scope
- [x] Create [`docs/08_session_management.md`](file:///E:/neuroshell-planner/docs/08_session_management.md) covering Redis schema and TTL
- [x] Create [`docs/09_metrics_observability.md`](file:///E:/neuroshell-planner/docs/09_metrics_observability.md) detailing MetricsCollector
- [x] Create [`docs/10_configuration_deployment.md`](file:///E:/neuroshell-planner/docs/10_configuration_deployment.md) covering env vars and redaction rules
- [x] Create [`docs/11_developer_guide.md`](file:///E:/neuroshell-planner/docs/11_developer_guide.md) with setup instructions and cURL tests
- [x] Create [`docs/12_glossary.md`](file:///E:/neuroshell-planner/docs/12_glossary.md) defining terms and proposal terminology
- [x] Create [`docs/13_master_plan.md`](file:///E:/neuroshell-planner/docs/13_master_plan.md) master plan document
- [x] Create [`docs/14_todo_checklist.md`](file:///E:/neuroshell-planner/docs/14_todo_checklist.md) this checklist document
- [x] Create [`docs/15_evaluation_report.md`](file:///E:/neuroshell-planner/docs/15_evaluation_report.md) research evaluation report with AST validation, RAG ablation, and fine-tuning results

---

## 11. Project Status & Remaining Unimplemented Work

- [x] **Phase 5.1:** Multi-command array generation in `PlannerOutput.command_sequence` for complex intents (`src/synthesis/command_synthesizer.py`, `src/api/main.py`)
- [x] **Phase 6.1:** Synthetic dataset creation in `data/synthesis_dataset/` (`c2_sft_full.csv`, `c2_sft_train.csv`, `c2_sft_test.csv`)
- [x] **Phase 6.2:** LoRA fine-tuning script execution for Gemma 2 model (`google/gemma-2-2b-it`)
- [x] **Phase 6.3:** LoRA adapter GGUF conversion & deployment in Ollama as `neuroshell-c2-gemma2:latest`
- [ ] **Phase 5.2:** Dynamic feedback loop processing execution logs from Component 3 (*Planned / Unimplemented*)
- [ ] **Phase 5.3:** Adaptive tool chaining based on session execution history (*Planned / Unimplemented*)
