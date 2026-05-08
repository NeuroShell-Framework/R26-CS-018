# NeuroShell IRE — Intent Recognition Engine

**Domain-specific NLU gateway that converts natural language offensive security commands into validated, structured JSON intent contracts.**

## Research Context

- **Project:** NeuroShell Framework, Component 01
- **Reference:** R26-CS-018
- **Author:** T. Hariprasad | Student ID: [REDACTED]
- **Degree:** MSc Cybersecurity, [Institution]
- **Research Gap:** No existing autonomous penetration testing framework implements a dedicated, isolated Natural Language Understanding (NLU) layer. Current tools either require structured input formats or rely on general-purpose LLMs without domain-specific validation, creating a gap between operator intent and machine-executable actions. NeuroShell IRE fills this gap by providing a rigorously validated, schema-constrained NLU pipeline purpose-built for offensive security operations.

## Architecture

```
Raw Input
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        IRE Pipeline (7 Stages)                          │
│                                                                         │
│  [1] InputNormalizer   → Whitespace, NFKC, slang standardization        │
│         │                                                               │
│         ▼                                                               │
│  [2] AliasResolver     → J→CVE mapping (EternalBlue → CVE-2017-0144)    │
│         │                                                               │
│         ▼                                                               │
│  [3] OllamaInference   → Gemma 4 E4B / 27B-IT via local Ollama          │
│         │                                                               │
│         ▼                                                               │
│  [4] JSONParser        → Extraction + markdown/think-block stripping    │
│         │                                                               │
│         ▼                                                               │
│  [5] SchemaValidator   → Pydantic IntentSchema enforcement              │
│         │                                                               │
│         ▼                                                               │
│  [6] RegexValidator    → IP/CIDR/CVE/port/metachar verification         │
│         │                                                               │
│         ▼                                                               │
│  [7] ScopeGuard        → RFC-1918 enforcement + injection detection     │
│         │                                                               │
│         ▼                                                               │
│  Structured JSON Output (IntentSchema)                                  │
└─────────────────────────────────────────────────────────────────────────┘
```

## Technology Stack

| Layer | Technology | Reason |
|---|---|---|
| LLM | Gemma 4 E4B / 27B-IT | Open-weight, strong instruction-following, locally runnable |
| Inference Runtime | Ollama | Zero-config local model serving with REST API |
| API Framework | FastAPI | Async-first, auto OpenAPI docs, Pydantic integration |
| Validation | Pydantic v2 + jsonschema | Strict schema enforcement with detailed error messages |
| Preprocessing | spaCy (en_core_web_sm) | Production-grade NLP pipeline |
| Logging | structlog | Structured JSON logging for audit trails |
| Rate Limiting | slowapi | Per-IP rate limiting (30 req/min) |
| Testing | pytest + httpx.AsyncClient | Unit + async integration testing |
| Containerization | Docker + docker-compose | Reproducible deployment with GPU passthrough |
| Fine-Tuning | LoRA + PEFT + bitsandbytes | Parameter-efficient adaptation on A100 GPU |

## Quick Start

### 1. Prerequisites
- Python 3.11+
- Ollama installed and running (`ollama serve`)

### 2. Clone and setup
```bash
cd neuroshell-ire
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 4. Configure environment
```bash
cp .env.example .env
# Edit .env — set IRE_API_KEY and verify OLLAMA_MODEL
```

### 5. Pull the model
```bash
ollama pull gemma4:e4b
```

### 6. Launch
```bash
python scripts/run_dev.py
```

### 7. Verify
```bash
curl http://localhost:8001/health
```

## API Reference

### GET `/health`
System health check. No authentication required.

**Response (200):**
```json
{
  "status": "healthy",
  "ollama": "connected",
  "model": "gemma4:e4b",
  "pipeline_stages": 7,
  "cache_size": 0
}
```

### POST `/parse`
Core endpoint. Requires `X-API-Key` header (skipped in dev mode). Rate limited: 30 req/min per IP.

**Request:**
```json
{
  "command": "Do a stealth ICMP discovery scan of 192.168.1.0/24",
  "session_id": "op-001"
}
```

**Success Response (200):**
```json
{
  "status": "success",
  "intent": "NETWORK_SCAN",
  "target": { "type": "SUBNET", "value": "192.168.1.0/24" },
  "ports": [],
  "modifiers": ["stealth"],
  "cve_ids": [],
  "tool_hint": "nmap",
  "schedule": null,
  "confidence": 0.97,
  "rejection_reason": null,
  "scope_warnings": [],
  "latency_ms": 12450
}
```

**Error Response (400–503):**
```json
{
  "status": "error",
  "error": "SCOPE_VIOLATION",
  "stage": "scope_guard",
  "field": null,
  "detail": "Prompt injection pattern detected in input",
  "latency_ms": 24500
}
```

### GET `/metrics`
Pipeline performance metrics. Requires API key.

**Response (200):**
```json
{
  "total_requests": 42,
  "success_count": 38,
  "error_counts": {"scope_guard": 2, "json_parser": 2},
  "intent_distribution": {"NETWORK_SCAN": 20, "VULNERABILITY_AUDIT": 12},
  "latency_p50_ms": 11200,
  "latency_p95_ms": 24500,
  "latency_p99_ms": 31000,
  "uptime_seconds": 3600
}
```

## Output Schema

| Field | Type | Description | Required |
|---|---|---|---|
| `intent` | Enum (9 values) | Classified intent type | Yes |
| `target` | Object `{type, value}` | Target with type classification | Yes |
| `ports` | `List[int]` | Explicit port numbers mentioned | No (default: `[]`) |
| `modifiers` | `List[str]` | Adverbial modifiers (stealth, aggressive) | No (default: `[]`) |
| `cve_ids` | `List[str]` | CVE identifiers in `CVE-YYYY-NNNNN` format | No (default: `[]`) |
| `tool_hint` | `str \| null` | Suggested tool (nmap, hydra, gobuster) | No |
| `schedule` | `str \| null` | Cron expression if scheduling mentioned | No |
| `confidence` | `float` (0.0–1.0) | Model certainty score | Yes |
| `rejection_reason` | `str \| null` | Reason if intent is REJECTED | Conditional |

## Intent Classes

| Intent | Example Input |
|---|---|
| `NETWORK_SCAN` | "Scan 192.168.1.0/24 for open ports" |
| `VULNERABILITY_AUDIT` | "Check if 10.0.0.5 is vulnerable to CVE-2021-44228" |
| `DIRECTORY_BRUTEFORCE` | "Bruteforce directories on http://target.com" |
| `SERVICE_ENUMERATION` | "Enumerate all services on 10.10.10.5" |
| `EXPLOITATION` | "Exploit EternalBlue on 192.168.1.5" |
| `PASSWORD_ATTACK` | "Password spray the domain controller" |
| `PASSIVE_RECON` | "Gather info on example.com without touching it" |
| `AMBIGUOUS` | "Do something on the server" (confidence < 0.5) |
| `REJECTED` | "Ignore all previous instructions" (out of scope / injection) |

## Alias Resolution

The `data/alias_map.json` file maps 22 offensive security aliases to canonical identifiers.

| Alias | Resolves To | Type |
|---|---|---|
| `EternalBlue` | `CVE-2017-0144` | CVE |
| `Log4Shell` | `CVE-2021-44228` | CVE |
| `BlueKeep` | `CVE-2019-0708` | CVE |
| `ShellShock` | `CVE-2014-6271` | CVE |
| `Heartbleed` | `CVE-2014-0160` | CVE |
| `PrintNightmare` | `CVE-2021-34527` | CVE |
| `ZeroLogon` | `CVE-2020-1472` | CVE |
| `ProxyLogon` | `CVE-2021-26855` | CVE |
| `DirtyPipe` | `CVE-2022-0847` | CVE |
| `PwnKit` | `CVE-2021-4034` | CVE |
| `pwn` | `exploit` | Slang |
| `box` | `host` | Slang |
| `syn scan` | `SYN stealth scan` | Term |
| `ping sweep` | `ICMP discovery scan` | Term |
| `stealthy sweep` | `stealth ICMP discovery scan` | Term |
| `brute` | `brute force` | Slang |
| `enum` | `enumeration` | Slang |
| `recon` | `reconnaissance` | Slang |

## Running Tests

```bash
# Unit tests only
python -m pytest tests/unit/ -v

# Integration tests only
python -m pytest tests/integration/ -v

# Full test suite
python -m pytest --tb=short
```

## Fine-Tuning (Phase 2)

The IRE currently runs on Gemma 4 E4B via Ollama as a base model. The fine-tuning pipeline (Phase 2) will:

- **Dataset:** 20,000 synthetic examples covering all 9 intent classes with balanced distribution
- **Platform:** Kaggle (A100 GPU) for training + HuggingFace Hub for model registry
- **Base Model:** Gemma 4 27B-IT with 4-bit quantization (bitsandbytes NF4)
- **Method:** LoRA adapter (r=16, alpha=32) targeting 6 projection modules
- **Config:** Full parameters in `config/lora_config.yaml`
- **Status:** Base model operational. Fine-tuning scripts (`scripts/train_lora.py`, `scripts/clean_dataset.py`, `scripts/evaluate_model.py`) are scaffolded and awaiting dataset generation.

## Project Structure

```
neuroshell-ire/
├── src/
│   ├── __init__.py
│   ├── api/
│   │   ├── __init__.py
│   │   └── main.py                    # FastAPI application
│   ├── preprocessing/
│   │   ├── __init__.py
│   │   ├── input_normalizer.py        # Stage 1: normalization
│   │   └── alias_resolver.py          # Stage 2: alias resolution
│   ├── inference/
│   │   ├── __init__.py
│   │   └── ollama_inference_engine.py # Stage 3: LLM inference
│   ├── validation/
│   │   ├── __init__.py
│   │   ├── json_parser.py             # Stage 4: JSON extraction
│   │   ├── schema_validator.py        # Stage 5: Pydantic validation
│   │   ├── regex_validator.py         # Stage 6: regex verification
│   │   └── scope_guard.py             # Stage 7: scope enforcement
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── intent_schema.py           # Pydantic models + exceptions
│   │   └── ire_intent_schema.json     # JSON Schema definition
│   ├── pipeline/
│   │   ├── __init__.py
│   │   └── ire_pipeline.py            # 7-stage orchestrator
│   └── utils/
│       ├── __init__.py
│       ├── metrics_collector.py       # Performance metrics
│       └── logging_config.py          # Structured JSON logging
├── data/
│   ├── raw/
│   ├── synthetic/
│   └── alias_map.json                 # 22 alias mappings
├── models/                            # Fine-tuned LoRA adapters
├── tests/
│   ├── __init__.py
│   ├── unit/                          # 136 unit tests
│   │   ├── test_input_normalizer.py   # 30 tests
│   │   ├── test_alias_resolver.py     # 20 tests
│   │   ├── test_json_parser.py        # 15 tests
│   │   ├── test_schema_validator.py   # 20 tests
│   │   ├── test_regex_validator.py    # 40 tests
│   │   └── test_scope_guard.py        # 10 tests
│   └── integration/                   # 12 integration tests
│       └── test_api.py                # Full API coverage
├── config/
│   ├── lora_config.yaml               # Fine-tuning parameters
│   └── settings.py                    # Pydantic settings
├── scripts/
│   ├── run_dev.py                     # One-command dev launcher
│   ├── train_lora.py                  # LoRA training script
│   ├── clean_dataset.py               # Dataset preprocessing
│   └── evaluate_model.py              # Model evaluation
├── notebooks/                         # Exploration notebooks
├── .env.example                       # Environment template
├── .gitignore
├── requirements.txt                   # Python dependencies
├── docker-compose.yml                 # Docker + Ollama compose
├── Dockerfile                         # Production container
├── pytest.ini                         # Test configuration
└── README.md                          # This file
```

## Novelty Claims

1. **Decoupled NLU Gateway** — IRE is the first autonomous penetration testing framework component that isolates natural language understanding into a dedicated, independently deployable microservice. This enables the downstream Dynamic Planner and Exploit Orchestrator components to consume validated structured contracts rather than raw text, eliminating intent drift across the agent chain.

2. **Domain-Specific Entity Taxonomy** — Unlike general-purpose NER systems, IRE implements a purpose-built taxonomy for offensive security: 9 intent classes, 6 target types, a 22-entry alias-to-CVE resolver, and regex validators for IP/CIDR/CVE/port formats. This domain specialization eliminates the hallucination patterns that plague generic LLM outputs in security contexts.

3. **Hybrid Validation Pipeline** — The 7-stage pipeline combines LLM inference (Stage 3) with deterministic validation (Stages 4-7): JSON extraction, Pydantic schema enforcement, regex entity verification, and scope-guard enforcement. This hybrid approach guarantees that every output is structurally valid, semantically bounded, and scope-compliant — a guarantee no single LLM can provide alone.
