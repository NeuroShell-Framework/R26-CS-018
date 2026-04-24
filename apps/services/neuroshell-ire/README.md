# NeuroShell IRE — Intent Recognition Engine

> **Component 01** of the [NeuroShell](https://github.com/neuroshell) autonomous penetration testing framework.

## Overview

The **Intent Recognition Engine (IRE)** is responsible for translating free-form natural language pentest commands into structured, validated intent objects that downstream NeuroShell components can act upon.

## Architecture

```
User Input
    └── Preprocessing (normalize + alias resolve)
            └── Ollama Inference (LLM intent classification)
                    └── Validation (JSON parse + schema + regex + scope guard)
                            └── Structured Intent Output (JSON)
```

## Project Structure

```
neuroshell-ire/
├── src/           # Core application source
│   ├── api/           # FastAPI application
│   ├── preprocessing/ # Input normalization & alias resolution
│   ├── inference/     # Ollama LLM inference engine
│   ├── validation/    # JSON parsing, schema, regex, scope guard
│   ├── schemas/       # Pydantic models & JSON Schema
│   ├── pipeline/      # End-to-end IRE orchestration pipeline
│   └── utils/         # Logging & metrics
├── data/          # Alias maps, raw & synthetic datasets
├── models/        # Fine-tuned LoRA adapters
├── tests/         # Unit & integration tests
├── config/        # App settings & LoRA config
├── scripts/       # Training, cleaning & evaluation scripts
└── notebooks/     # Research & exploration notebooks
```

## Quick Start

```bash
# 1. Clone and enter directory
cd neuroshell-ire

# 2. Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy environment variables
copy .env.example .env
# Edit .env with your settings

# 5. Start the API
uvicorn src.api.main:app --port 8001 --reload

# 6. Verify health
# GET http://localhost:8001/health
```

## Development Phases

| Phase | Focus |
|-------|-------|
| 1 | Project setup, logging, settings |
| 2 | Preprocessing — normalization & alias resolution |
| 3 | Validation — JSON parser, schema, regex, scope guard |
| 4 | Ollama inference engine integration |
| 5 | Pipeline orchestration |
| 6 | FastAPI endpoints, Docker |
| 7 | LoRA fine-tuning on Kaggle |

## Status

🚧 **Scaffolding complete — implementation in progress**
