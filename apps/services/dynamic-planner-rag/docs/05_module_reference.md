# 05 — Module Reference

Detailed class and function documentation for every module in `src/`.

---

## 5.1 `src/api/main.py`

**FastAPI application entry point.** Initialises all service instances and defines all HTTP endpoints.

### Application Config

```python
app = FastAPI(
    title       = "NeuroShell Dynamic Planner",
    description = "C2 RAG-powered command synthesis engine",
    version     = "1.0.0"
)
```

### Global Instances

| Variable | Type | Description |
|---|---|---|
| `interpreter` | `IntentInterpreter` | Singleton; stateless |
| `constructor` | `QueryConstructor` | Singleton; stateless |
| `retriever` | `VectorRetriever` | Singleton; holds ChromaDB client + embedding model |
| `assembler` | `ContextAssembler` | Singleton; stateless |
| `synthesizer` | `CommandSynthesizer` | Singleton; stateless |
| `tool_selector` | `ToolSelector` | Singleton; loads `tool_map.json` at startup |
| `validator` | `CommandValidator` | Singleton; stateless |
| `safety` | `SafetyFilter` | Singleton; stateless |
| `session_mgr` | `SessionContextManager` | Singleton; holds Redis client |
| `metrics` | `MetricsCollector` | Singleton; accumulates in-memory metrics list |

### Endpoints

| Function | Route | Method | Auth |
|---|---|---|---|
| `health()` | `/health` | GET | None |
| `plan(request, x_api_key)` | `/plan` | POST | `x-api-key` |
| `available_tools()` | `/tools/available` | GET | None |
| `get_metrics(x_api_key)` | `/metrics` | GET | `x-api-key` |

#### `health() → dict`

Pings Redis and counts KB chunks. Returns a status dict.

#### `plan(request: PlanRequest, x_api_key: str) → PlannerOutput`

Core orchestration function. Executes the 9-step pipeline. Raises `HTTPException` for auth failures, rejected intents, safety failures, or unexpected exceptions.

#### `available_tools() → dict`

Returns `{"tools": ["nmap", "nikto", "gobuster"], "kb_chunks": <count>}`.

#### `get_metrics(x_api_key: str) → dict`

Returns `MetricsCollector.get_summary()`. Requires valid API key.

---

## 5.2 `src/intent/intent_interpreter.py`

### Class: `IntentInterpreter`

Converts `IREIntentContract` to a flat `params` dict for downstream pipeline steps.

#### `interpret(contract: IREIntentContract) → dict`

```python
def interpret(self, contract: IREIntentContract) -> dict
```

**Target resolution (priority order):**
1. `contract.target_value` (enriched C1 format)
2. `contract.target["value"]` (legacy dict format)
3. Empty string (fallback)

**Port resolution (priority order):**
1. `contract.tool_parameters.ports` (if non-empty)
2. `contract.ports` (legacy)
3. `_default_ports(intent, tool_hint)` (smart defaults)

**Modifier resolution (priority order):**
1. `contract.tool_parameters.flags` (enriched C1 format)
2. `contract.modifiers` (legacy)

**Tool hint resolution (priority order):**
1. `contract.primary_tool` (enriched format)
2. `contract.tool_hint` (legacy)

**`multi_step` flag:** Set to `True` when `intent ∈ {EXPLOITATION, VULNERABILITY_AUDIT}` AND `confidence > 0.85`.

#### `_default_ports(intent: str, tool_hint: str | None) → list`

```python
def _default_ports(self, intent: str, tool_hint: str | None) -> list
```

Returns smart default port lists based on intent and tool.

| Condition | Returns |
|---|---|
| `tool_hint == "nikto"` OR `intent == "VULNERABILITY_AUDIT"` | `[80]` |
| `intent == "DIRECTORY_BRUTEFORCE"` | `[80]` |
| All other | `[]` |

---

## 5.3 `src/intent/query_constructor.py`

### Module-Level Constants

#### `MODIFIER_TEXT_MAP: dict[str, str]`

Maps short modifier keys to expanded semantic text for richer RAG retrieval.

#### `QUERY_TEMPLATES: dict[str, str]`

Maps intent codes to query template strings with `{modifiers}`, `{target_type}`, `{ports}`, `{cve}` placeholders.

### Class: `QueryConstructor`

#### `build_query(params: dict) → str`

```python
def build_query(self, params: dict) -> str
```

1. Extracts `intent`, `modifiers`, `target_type`, `ports`, `cve_ids` from params.
2. Maps each modifier to its expanded text via `MODIFIER_TEXT_MAP`.
3. Selects the appropriate template from `QUERY_TEMPLATES`.
4. Formats the template with expanded values.
5. Normalises whitespace with `re.sub(r"\s+", " ", query)`.
6. Returns the final query string.

**Example:**
```python
params = {
    "intent": "NETWORK_SCAN",
    "modifiers": ["stealth"],
    "target_type": "IP",
    "ports": [],
    "cve_ids": []
}
# Returns: "nmap SYN stealth scan half-open technique network port scan syntax flags ip"
```

---

## 5.4 `src/rag/vector_retriever.py`

### Class: `VectorRetriever`

Manages the ChromaDB connection and embedding model for semantic document retrieval.

#### `__init__(self)`

- Creates a `chromadb.PersistentClient` pointing to `knowledge_base/chroma_db`.
- Loads `all-MiniLM-L6-v2` from `sentence-transformers`.
- Opens (or creates) the `tool_documentation` collection with `hnsw:space=cosine`.

#### `retrieve(query: str, tool_hint: str = None, top_k: int = 3, score_threshold: float = DEFAULT_SCORE_THRESHOLD) → list[dict]`

```python
def retrieve(self, query: str, tool_hint: str = None, top_k: int = 3, score_threshold: float = DEFAULT_SCORE_THRESHOLD) -> list[dict]
```

**Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `query` | `str` | — | Semantic query string from `QueryConstructor` |
| `tool_hint` | `str` | `None` | If set, filters ChromaDB results to this tool only |
| `top_k` | `int` | `3` | Maximum number of documents to return |
| `score_threshold` | `float` | `0.30` | Minimum cosine similarity score (`1.0 - distance`); chunks below this score are filtered out |

---

## 5.5 `src/rag/context_assembler.py`

### Class: `ContextAssembler`

Constructs the LLM prompt from retrieved documents and intent parameters.

#### `assemble(retrieved_docs: List[Dict], intent_contract: dict) → str`

```python
def assemble(self, retrieved_docs: List[Dict], intent_contract: dict) -> str
```

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `retrieved_docs` | `List[Dict]` | Docs from `VectorRetriever.retrieve()` |
| `intent_contract` | `dict` | Params dict from `IntentInterpreter.interpret()` |

**Algorithm:**
1. Groups documents by tool name into `tool_sections`.
2. Formats each group as `=== TOOLNAME DOCUMENTATION ===\n<chunks>`.
3. Joins all sections with `\n\n`.
4. Wraps in the Kali Linux expert prompt template.
5. Returns the prompt string (without the target-reinforcement line; that is appended by `main.py`).

---

## 5.6 `src/synthesis/tool_selector.py`

### Class: `ToolSelector`

Resolves the definitive tool name using a priority-based decision chain.

#### `__init__(self, tool_map_path: str = None)`

Loads `data/tool_map.json` from a path resolved relative to this file's location.

#### `select(intent, tool_hint=None, top_retrieval_source=None) → str | None`

```python
def select(self, intent, tool_hint=None, top_retrieval_source=None) -> str | None
```

**Priority chain:**

| Priority | Source | Condition |
|---|---|---|
| 1 | `tool_hint` | Must be in `SUPPORTED_TOOLS = {nmap, nikto, gobuster}` |
| 2 | `top_retrieval_source` | Must be in `SUPPORTED_TOOLS` |
| 3 | `tool_map[intent][0]` | First tool in the intent's mapped list |
| — | `None` (→ `"unknown"`) | No match found |

> **Output destination:** The resolved tool name is stored in the local variable `tool` in `main.py` and written directly to `PlannerOutput.tool`. It is **not passed into `CommandSynthesizer.synthesize()`**. The synthesizer receives `(prompt, params, docs)` only.

---

## 5.7 `src/synthesis/command_synthesizer.py`

### Class: `CommandSynthesizer`

Calls the local Ollama LLM with the assembled prompt and returns the generated command.

#### `synthesize(prompt: str, params: dict, docs: List[Dict]) → dict`

```python
def synthesize(self, prompt: str, params: dict, docs: List[Dict]) -> dict
```

> **Design note:** The RAG pipeline is NOT re-run here. `main.py` is the single orchestration point. `CommandSynthesizer` is intentionally thin — it only calls Ollama and cleans the output.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `prompt` | `str` | Fully assembled LLM prompt from `ContextAssembler` + target reinforcement |
| `params` | `dict` | Interpreted params; may contain `_query_used` for logging |
| `docs` | `List[Dict]` | Retrieved docs; used to extract `retrieval_sources` |

**Returns:**
```json
{
  "command": "<primary bash command>",
  "command_sequence": ["<command 1>", "<command 2>"],
  "retrieval_sources": ["nmap", "nmap", "nmap"],
  "query_used": "<RAG query string>"
}
```

**Ollama call config:**
- Model: value of `OLLAMA_MODEL` env var (default production: `gemma4:e4b`; experimental fine-tuned model: `neuroshell-c2-gemma2:latest`)
- System message: `"You are a Kali Linux command generator. Output ONLY a valid command. Do not explain."`
- Post-processing: strips markdown fences (` ```bash ` / ` ``` `) and parses multi-command sequences when `multi_step` is set.

---

## 5.8 `src/validation/safety_filter.py`

### Class: `SafetyFilter`

Blocks dangerous commands and enforces RFC-1918 target restriction.

#### `validate(command: str, target: str) → Tuple[bool, List[str]]`

```python
def validate(self, command: str, target: str) -> Tuple[bool, List[str]]
```

**Returns:** `(is_safe: bool, flags: list[str])`

**Blocked patterns (regex, case-insensitive):**

| Pattern | Threat |
|---|---|
| `rm\s+-rf` | Destructive file removal |
| `mkfs` | Filesystem overwrite |
| `dd\s+if=` | Raw disk write |
| `:\(\)\{:\|:&\};:` | Fork bomb |
| `chmod\s+777\s+/` | World-writable root |
| `> /dev/sd` | Disk device write |
| `wget.+\|\s*bash` | Remote code execution via wget |
| `curl.+\|\s*bash` | Remote code execution via curl |
| `nc\s+-e\s+/bin` | Netcat shell bind |
| `bash\s+-i\s+>&` | Reverse shell |

**Allowed target ranges:**

| CIDR | Pattern |
|---|---|
| `192.168.0.0/16` | `^192\.168\.` |
| `10.0.0.0/8` | `^10\.` |
| `172.16.0.0/12` | `^172\.(1[6-9]|2[0-9]|3[01])\.` |
| Loopback | `^127\.` |
| Localhost | `localhost` |

#### `_is_allowed_target(target: str) → bool`

Internal helper that tests the target string against `ALLOWED_TARGETS` patterns.

---

## 5.9 `src/validation/command_validator.py`

### Class: `CommandValidator`

Performs structural validation of the synthesized command.

#### `validate(command: str, expected_tool: str) → Tuple[bool, List[str]]`

```python
def validate(self, command: str, expected_tool: str) -> Tuple[bool, List[str]]
```

**Returns:** `(passed: bool, issues: list[str])`

> **Enforcement:** If `validate()` returns `passed = False` due to a fatal structural check (empty command, multi-line command, or tool prefix mismatch), `main.py` records metrics with `success = False` and raises `HTTPException(status_code=422)` (Unprocessable Entity).

**Validation checks (in order):**

| Check | Fatal? | Issue Message |
|---|---|---|
| Empty command | Yes | `ERROR: empty command` |
| Multi-line command | Yes | `ERROR: multi-line command not allowed` |
| Wrong tool prefix | Yes | `ERROR: command does not start with expected tool '<tool>'` |
| Missing required flags | No (warning) | `WARNING: command missing expected flags for <tool>` |
| No private IP | No (warning) | `WARNING: no private IP found in command` |

**Tool-specific config:**

| Tool | Regex Pattern | Required Flags (any-of) |
|---|---|---|
| `nmap` | `^nmap\s+` | `-s`, `-p`, `--top-ports`, `-A`, `-sn` |
| `nikto` | `^nikto\s+` | `-h` |
| `gobuster` | `^gobuster\s+(dir\|dns\|vhost\|fuzz)\s+` | `-u`, `-w` |

---

## 5.10 `src/session/session_context_manager.py`

### Class: `SessionContextManager`

Redis-backed session state manager with 1-hour TTL and seamless in-memory dictionary fallback (`self._memory_fallback`) for Redis graceful degradation.

#### `get_last_target(session_id: str) → str | None`

Extracts the most recent valid target seen in the session (`targets_seen`). Excludes empty strings and `"UNKNOWN"`. Used by `main.py` for target recovery when an incoming request lacks a valid target.

#### `get_session(session_id: str) → dict`

Returns the session object from Redis (or `self._memory_fallback` if Redis is offline), or a fresh default session if not found.

#### `update_session(session_id: str, command: str, tool: str, target: str)`

Updates session lists (deduplicating valid targets and tools), updates `last_updated`, and saves to Redis with a 3600-second TTL (and to `self._memory_fallback`).

#### `clear_session(session_id: str)`

Deletes `session:{session_id}` from Redis and `self._memory_fallback`.

---

## 5.11 `src/utils/metrics_collector.py`

### Class: `MetricsCollector`

In-memory metrics accumulator. Resets on server restart.

#### `start_timer() → float`

Returns `time.time()`.

#### `record(session_id, intent, tool, start_time, success, safety_flags) → int`

Appends a metrics entry and returns `latency_ms`.

**Entry schema:**
```json
{
  "timestamp": "2026-08-24T07:00:00",
  "session_id": "sess-001",
  "intent": "NETWORK_SCAN",
  "tool": "nmap",
  "latency_ms": 3214,
  "success": true,
  "safety_flags": []
}
```

#### `get_summary() → dict`

Returns aggregate metrics:
```json
{
  "total": 42,
  "successful": 39,
  "failed": 3,
  "avg_latency_ms": 3108
}
```
