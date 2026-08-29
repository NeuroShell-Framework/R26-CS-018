# 12 — Glossary

Definitions for all terms, acronyms, intent codes, and technical concepts used in the NeuroShell C2 Dynamic Planner documentation.

---

## A

**all-MiniLM-L6-v2**  
The sentence-transformer embedding model used by C2. Produces 384-dimensional vectors. Used for both ingestion (encoding document chunks) and retrieval (encoding query strings).

**AMBIGUOUS**  
An intent code returned by C1 when it cannot classify the user's request with sufficient confidence. C2 will attempt to plan for ambiguous intents but quality may be lower.

**API Key (`API_KEY`)**  
A shared secret passed in the `x-api-key` HTTP header to authenticate requests to `/plan` and `/metrics`. Configured via the `API_KEY` environment variable.

---

## C

**C1 (IRE — Intent Recognition Engine)**  
The upstream NeuroShell component that processes natural language input and produces a structured `IREIntentContract`. C2 consumes C1's output.

**C2 (Dynamic Planner)**  
This component. Receives `IREIntentContract` from C1, performs RAG-based retrieval, synthesizes a Kali Linux bash command via a local LLM, validates it, and returns a `PlannerOutput`.

**C3 (Adaptive Execution & Error Recovery Engine)**  
The downstream NeuroShell component that receives C2's `PlannerOutput` and executes the synthesized command on the target system. It is also responsible for error recovery and adaptive retry logic. C2 does **not** execute commands — that is exclusively C3's responsibility.

**ChromaDB**  
An open-source vector database used as C2's knowledge store. Operates in embedded (file-based) mode. Collection: `tool_documentation`.

**CommandSynthesizer**  
The module (`src/synthesis/command_synthesizer.py`) that calls Ollama and returns the generated command. It is intentionally thin — it does not re-run RAG.

**CommandValidator**  
The module (`src/validation/command_validator.py`) that validates structural correctness of the synthesized command. Fatal structural validation failures (empty command, multi-line command, tool prefix mismatch) cause `main.py` to raise `HTTPException(422)` (Unprocessable Entity).


**ContextAssembler**  
The module (`src/rag/context_assembler.py`) that formats retrieved documents and intent parameters into the LLM prompt.

**Cosine Similarity**  
The distance metric used by ChromaDB. Score is computed as `1.0 - cosine_distance`. Higher scores indicate more relevant documents.

---

## D

**DIRECTORY_BRUTEFORCE**  
Intent code for enumerating hidden directories or files on a web server using a wordlist. Primary tool: `gobuster`.

---

## E

**Enriched C1 Format**  
The C1 v2 contract format using flat fields (`target_value`, `target_type`, `primary_tool`, `tool_parameters`). Preferred over the legacy nested format.

**EXPLOITATION**  
Intent code for exploiting a known vulnerability (often via CVE). No default tool in `tool_map.json`; requires `tool_hint` or `primary_tool`.

---

## G

**Gemma (`gemma4:e4b`)**  
The default LLM model used by C2. A Google-developed model served locally via Ollama. The model name is configurable via `OLLAMA_MODEL`.

**Gobuster**  
A web directory/file enumeration tool. C2 supports `dir`, `dns`, `vhost`, and `fuzz` subcommands.

---

## H

**HNSW**  
Hierarchical Navigable Small World — the approximate nearest-neighbor algorithm used by ChromaDB for fast vector search.

**Hydra**  
A password brute-force tool. Included in `ALLOWED_TOOLS` in `SafetyFilter` but not yet fully integrated with tool-specific validation.

---

## I

**IREIntentContract**  
The primary inter-component contract schema. Produced by C1, consumed by C2. Contains the intent, target, tool hints, modifiers, ports, CVE IDs, confidence score, and safety metadata. Defined in `src/schemas/models.py`.

**IntentInterpreter**  
The module (`src/intent/intent_interpreter.py`) that converts `IREIntentContract` into a flat `params` dict used by all downstream pipeline steps.

---

## K

**Knowledge Base (KB)**  
The collection of tool documentation text files stored in `knowledge_base/raw_docs/` and indexed as vector embeddings in ChromaDB.

---

## L

**Legacy Format**  
The C1 v1 contract format using the nested `intent_contract` object and `target: {type, value}` dict. Supported for backward compatibility.

**Latency (`latency_ms`)**  
End-to-end request processing time in milliseconds, measured from the start of `plan()` to the `metrics.record()` call.

---

## M

**MetricsCollector**  
The module (`src/utils/metrics_collector.py`) that accumulates per-request metrics in memory. Resets on server restart.

**MODIFIER**  
A flag or qualifier that modifies the behavior of the synthesized command. Examples: `stealth`, `aggressive`, `ssl`, `full`, `evasion`.

**Multi-step**  
A boolean key computed by `IntentInterpreter` and placed in the `params` dict. Set to `True` when `intent ∈ {EXPLOITATION, VULNERABILITY_AUDIT}` AND `confidence > 0.85`. When active, `CommandSynthesizer` parses an ordered sequence of bash commands into `command_sequence`, with each command independently validated.

---

**N**

**neuroshell-c2-gemma2:latest**  
The verified experimental fine-tuned Gemma 2 model deployed in Ollama. Created via SFT LoRA fine-tuning on `google/gemma-2-2b-it` (`q_proj+v_proj, r=16, alpha=32`), achieving a +33.33% accuracy gain over base Gemma 2. Base `gemma4:e4b` is retained as the default production model.

---

## N

**NETWORK_SCAN**  
Intent code for port scanning a network target. Primary tool: `nmap`.

**Nikto**  
A web server vulnerability scanner. Primary tool for `VULNERABILITY_AUDIT` intents.

**Nmap**  
A network exploration and port scanning tool. Primary tool for `NETWORK_SCAN` and `SERVICE_ENUMERATION` intents.

---

## O

**Ollama**  
A tool for running large language models locally. C2 uses the `ollama` Python client to call the `gemma4:e4b` model (or any model specified by `OLLAMA_MODEL`).

---

## P

**PASSIVE_RECON**  
Intent code for passive reconnaissance (OSINT, DNS lookups, WHOIS). No default tool in `tool_map.json`.

**PASSWORD_ATTACK**  
Intent code for password brute-force attacks. Primary tool: `hydra` (not yet tool-validated in C2 v1.0).

**PlannerOutput**  
The HTTP response schema for successful `/plan` requests. Contains the synthesized command, tool, session ID, validation status, safety flags, and latency.

**PlanRequest**  
The HTTP request body schema for `POST /plan`. Supports both enriched and legacy formats.

---

## Q

**QueryConstructor**  
The module (`src/intent/query_constructor.py`) that converts the `params` dict into a semantic query string for ChromaDB retrieval.

---

## R

**RAG (Retrieval-Augmented Generation)**  
A technique where relevant documents are retrieved from a knowledge base and injected into the LLM prompt to ground the model's output in factual documentation.

**RFC-1918**  
The IETF standard defining private IPv4 address ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`. C2's `SafetyFilter` only permits targets within these ranges.

**REJECTED**  
An intent code indicating that C1 explicitly blocked the user's request. C2 intercepts this before any RAG or LLM processing and returns HTTP 400.

**Retrieval Sources**  
The list of tool names from documents retrieved during RAG, returned in `PlannerOutput.retrieval_sources`.

---

## S

**SafetyFilter**  
The module (`src/validation/safety_filter.py`) that blocks dangerous commands and enforces RFC-1918 target restrictions. Failures are fatal (HTTP 400).

**SentenceTransformer**  
The Python library from Hugging Face used to encode text into embeddings. C2 uses the `all-MiniLM-L6-v2` model.

**SERVICE_ENUMERATION**  
Intent code for enumerating services running on open ports (banner grabbing, version detection). Primary tool: `nmap` with `-sV`.

**Session**  
A Redis-backed state object keyed by `session_id` that tracks targets seen, commands run, and tools used across multiple requests in a single engagement.

**SessionContextManager**  
The module (`src/session/session_context_manager.py`) that manages Redis session CRUD with a 1-hour TTL, target recovery (`get_last_target`), and graceful degradation to an in-memory dictionary fallback store when Redis is offline.


**sub_intent**  
An optional secondary intent qualifier provided by C1. Currently informational in C2 v1.0.

---

## T

**Target Reinforcement**  
An additional line appended to the LLM prompt by `main.py` after `ContextAssembler.assemble()`:  
`"IMPORTANT: Use this exact target in the command: <target_value>"`  
This ensures the LLM does not substitute a placeholder or example IP.

**Tool Hint**  
A tool recommendation from C1 (`primary_tool` in enriched format, `tool_hint` in legacy format). Highest priority in `ToolSelector`'s decision chain.

**ToolParameters**  
A Pydantic model containing structured tool configuration from C1: `flags`, `ports`, `wordlist`, `target`, `suggested_command`.

**ToolSelector**  
The module (`src/synthesis/tool_selector.py`) that resolves the definitive tool name using a priority chain: C1 tool hint → RAG top source → `tool_map.json` fallback.

**tool_map.json**  
A JSON file at `data/tool_map.json` mapping intent codes to ordered lists of fallback tools. Used as the lowest-priority option in `ToolSelector`.

**TTL (Time to Live)**  
The expiry duration for Redis session keys. Set to `3600` seconds (1 hour). Resets on every `update_session()` call.

---

## V

**VectorRetriever**  
The module (`src/rag/vector_retriever.py`) that manages ChromaDB connections and performs cosine similarity search for document retrieval.

**VULNERABILITY_AUDIT**  
Intent code for web vulnerability scanning. Primary tool: `nikto`. Triggers `multi_step = True` when confidence > 0.85.

---

## W

**Wordlist**  
A file containing candidate paths, passwords, or subdomains for brute-force attacks. Referenced in `ToolParameters.wordlist` and passed to gobuster's `-w` flag.
