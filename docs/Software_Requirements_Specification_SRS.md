# COVER PAGE

# Requirements Specification (SRS) / Design Document (DD)
## Project ID: R26-CS-018
### Project Title: NeuroShell Core Framework — Autonomous NLU-Driven Offensive Security Microservices Infrastructure

**Student Details:**  
- **Name:** T. Hariprasad  
- **Student ID:** R26-CS-018  
- **Degree Program:** MSc Cybersecurity  

**Supervisor:** Academic Supervisor / Review Board  
**Date of Submission:** August 11, 2026  

---

# 4 Supporting Information
## 4.1 Table of Contents and Index

### Table of Contents
- [Cover Page](#cover-page)
- [4.1 Table of Contents and Index](#41-table-of-contents-and-index)
- [1 Introduction](#1-introduction)
  - [1.1 Purpose](#11-purpose)
  - [1.2 Scope](#12-scope)
  - [1.3 Definitions, Acronyms, and Abbreviations](#13-definitions-acronyms-and-abbreviations)
  - [1.5 Overview](#15-overview)
- [2 Overall Descriptions](#2-overall-descriptions)
  - [2.1 Product Perspective](#21-product-perspective)
    - [2.1.1 System Interfaces](#211-system-interfaces)
    - [2.1.2 User Interfaces](#212-user-interfaces)
    - [2.1.3 Hardware Interfaces](#213-hardware-interfaces)
    - [2.1.4 Software Interfaces](#214-software-interfaces)
    - [2.1.5 Communication Interfaces](#215-communication-interfaces)
    - [2.1.6 Memory Constraints](#216-memory-constraints)
    - [2.1.7 Operations](#217-operations)
    - [2.1.8 Site Adaptation Requirements](#218-site-adaptation-requirements)
  - [2.2 Product Functions](#22-product-functions)
  - [2.3 User Characteristics](#23-user-characteristics)
  - [2.4 Constraints](#24-constraints)
  - [2.5 Assumptions and Dependencies](#25-assumptions-and-dependencies)
  - [2.6 Apportioning of Requirements](#26-apportioning-of-requirements)
- [3 Specific Requirements](#3-specific-requirements)
  - [3.1 External Interface Requirements](#31-external-interface-requirements)
    - [3.1.1 User Interfaces](#311-user-interfaces)
    - [3.1.2 Hardware Interfaces](#312-hardware-interfaces)
    - [3.1.3 Software Interfaces](#313-software-interfaces)
    - [3.1.4 Communication Interfaces](#314-communication-interfaces)
  - [3.2 Classes / Objects](#32-classes--objects)
  - [3.3 Performance Requirements](#33-performance-requirements)
  - [3.4 Design Constraints](#34-design-constraints)
  - [3.5 Software System Attributes](#35-software-system-attributes)
    - [3.5.1 Reliability](#351-reliability)
    - [3.5.2 Availability](#352-availability)
    - [3.5.3 Security](#353-security)
    - [3.5.4 Maintainability](#354-maintainability)
  - [3.6 Other Requirements](#36-other-requirements)
- [4 Supporting Information (Continued)](#4-supporting-information-continued)
  - [4.2 Appendices](#42-appendices)
    - [Appendix A: Alias Map (data/alias_map.json) Matrix](#appendix-a-alias-map-dataalias_mapjson-matrix)
    - [Appendix B: Key API Endpoint Request/Response Schemas](#appendix-b-key-api-endpoint-requestresponse-schemas)
    - [Appendix C: Container Resource Deployment Specs](#appendix-c-container-resource-deployment-specs)
- [1.4 References](#14-references)

---

# 1 Introduction

## 1.1 Purpose
*Comment: Purpose of the document and not the purpose of the software.*

The purpose of this **Software Requirements Specification (SRS) / Design Document (DD)** is to provide a complete, authoritative, and formal description of the technical requirements, functional specifications, system architecture, object domain models, boundary constraints, and quality attributes of the **NeuroShell Core Framework (Project ID: R26-CS-018)**. 

This document serves as:
1. **Developer Baseline:** A precise specification for core developers and microservice maintainers building, extending, and refactoring software components within the monorepo.
2. **Quality Assurance & Verification Guide:** A benchmark for test engineers writing unit, integration, and performance test suites (`pytest`).
3. **Academic & Security Auditor Manual:** A formal documentation submission for academic evaluation, vulnerability reviews, and compliance auditing of autonomous offensive security NLU systems.

## 1.2 Scope
*Comment: What aspects of the application this document tends to cover?*

This document covers all software layers, microservices, containerization infrastructure, gateway configurations, and shared libraries comprising the **NeuroShell Core** microservices monorepo. Specifically, it specifies requirements for:

1. **Kong API Gateway Service (`apps/api-gateway` / `infra/kong`):** Reverse proxy routing, rate-limiting (60 req/min), header transformation, CORS policies, and centralized ingress.
2. **Intent Recognition Engine (NeuroShell IRE) (`apps/services/neuroshell-ire` / `apps/services/intent-recognition`):** A 7-stage domain-specific Natural Language Understanding (NLU) pipeline converting natural language offensive security requests into schema-validated JSON intent contracts. Powered by local LLM inference via Ollama (`gemma4:e4b` / `27B-IT`).
3. **Dynamic Planner RAG Service (`apps/services/dynamic-planner-rag`):** Retrieval-Augmented Generation planner generating ordered execution graphs, evaluating sub-task constraints, and calculating success probabilities.
4. **AI Vulnerability Analysis Service (`apps/services/ai-vulnerability-analysis`):** Automated vulnerability auditing engine producing risk scores, attack vectors, and CWE/CVSS mappings.
5. **Adaptive Execution Error Recovery Service (`apps/services/adaptive-execution-error-recovery`):** Self-healing runtime engine categorizing errors (timeout, resource, authorization) and executing recovery strategies (circuit breaker, retry, fallback).
6. **NeuroShell Shared Core (`shared`):** Centralized JWT authentication, custom Pydantic response models, structlog logging utilities, and global exception handlers.
7. **Infrastructure & DevOps (`infra/docker`, `.github/workflows`):** Docker Compose orchestration profiles (dev vs. prod), health checks, environment management, and automated CI pipelines.

---

## 1.3 Definitions, Acronyms, and Abbreviations
*Comment: Glossary of terms that will be used throughout the documents, as well as in other documents based on this one.*

| Term / Acronym | Full Form / Definition |
|---|---|
| **SRS** | Software Requirements Specification |
| **DD** | Design Document |
| **IRE** | Intent Recognition Engine — The domain-specific NLU gateway for NeuroShell. |
| **NLU** | Natural Language Understanding — Branch of AI focused on parsing human text into structured machine representation. |
| **RAG** | Retrieval-Augmented Generation — Pattern supplementing LLM prompts with domain knowledge retrieved from external stores. |
| **CVE** | Common Vulnerabilities and Exposures — Standardized dictionary of publicly known cybersecurity vulnerabilities. |
| **CVSS** | Common Vulnerability Scoring System — Open framework for communicating the characteristics and severity of software vulnerabilities. |
| **CWE** | Common Weakness Enumeration — Category system for software weaknesses and vulnerabilities. |
| **RFC-1918** | Request for Comments 1918 — Address Allocation for Private Internets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). |
| **LLM** | Large Language Model — Deep learning models capable of text generation and understanding (e.g., Gemma 4). |
| **LoRA / PEFT** | Low-Rank Adaptation / Parameter-Efficient Fine-Tuning — Techniques for efficient LLM customization. |
| **ASGI** | Asynchronous Server Gateway Interface — Standard interface between async Python web servers and applications. |
| **CORS** | Cross-Origin Resource Sharing — Browser security mechanism controlling cross-domain HTTP requests. |
| **JWT** | JSON Web Token — Compact, URL-safe means of representing claims between two parties. |

---

## 1.5 Overview
*Comment: Overview of the software. Its main goals, tasks and users.*

**NeuroShell Core** is an enterprise-grade, autonomous, microservices-based offensive security execution framework. Traditional penetration testing tools rely on rigid command-line syntax (e.g., `nmap -sV -p 80 192.168.1.1`), while existing LLM security agents risk generating dangerous, unconstrained commands or hallucinated actions. 

NeuroShell bridges this gap by enforcing an isolated, 7-stage NLU parsing pipeline (NeuroShell IRE) that ingests raw natural language requests, standardizes slang and security aliases, routes prompts through a locally served open-weight LLM (Gemma 4), and strictly enforces typed Pydantic JSON intent schemas before any execution plan is formed.

### Key System Goals:
1. **Safety & Scope Enforcement:** Guarantee through `ScopeGuard` that natural language intent targets remain within authorized network boundaries (RFC-1918 private subnets) and reject prompt injection attempts.
2. **Deterministic Execution Contracts:** Translate ambiguous operator natural language into validated structured JSON contracts containing intent categories, target types, ports, modifiers, and CVE bindings.
3. **Adaptive Planning & Recovery:** Dynamically plan multi-step security assessments via RAG and automatically recover from runtime failures using automated error categorization and circuit breakers.
4. **Decoupled Monorepo Microservices:** Provide high scalability, independent container deployment, rate limiting, and centralized API management via Kong API Gateway.

---

# 2 Overall Descriptions

## 2.1 Product Perspective
*Comment: In this section software should be compared with other related or competing products, which is a good way to provide perspective of our product.*

NeuroShell Core occupies a unique space between traditional manual security tools (Metasploit, Nmap, Burp Suite) and unconstrained AI agents (AutoGPT, generic LLM security scripts).

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Kong API Gateway                                 │
│                       (Port 8000 - HTTP, 8443 - HTTPS)                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
          ┌───────────────────────────┼───────────────────────────┐
          │                           │                           │
          ▼                           ▼                           ▼
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│ adaptive-execution  │    │ ai-vulnerability    │    │ intent-recognition  │
│ -error-recovery     │    │ -analysis          │    │ (neuroshell-ire)    │
│ (Port 8001)        │    │ (Port 8002)        │    │ (Port 8004 / 8001) │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
                                       │
                                       ▼
                          ┌─────────────────────┐
                          │ dynamic-planner    │
                          │ -rag               │
                          │ (Port 8003)       │
                          └─────────────────────┘
```

### Comparative Analysis:
- **Traditional Security CLIs (Nmap, Metasploit):** Require exact CLI flag syntax; zero natural language understanding; no contextual adaptation or self-healing.
- **Unconstrained AI Security Agents:** Direct LLM output executed in shell environment; high risk of prompt injection, out-of-scope subnet targeting, hallucinated CLI flags, and unhandled runtime exceptions.
- **NeuroShell Core (This Product):** Combines local open-weight LLMs (Gemma 4 via Ollama) with a multi-stage validation pipeline (NeuroShell IRE), Kong API Gateway rate-limiting, Pydantic schema contracts, and self-healing error recovery.

---

### 2.1.1 System Interfaces
- **Operating System:** Supported on Linux (Ubuntu 22.04 LTS recommended) and Windows 11 (via WSL2 / Docker Desktop).
- **Process Management:** Docker Engine v24.0+ and Docker Compose v2.20+.
- **ASGI Web Server:** Python Uvicorn 0.32.0 running FastAPI 0.115.0 inside Linux container base (`python:3.11-slim`).
- **Subprocess / System Signals:** Standard POSIX signal handlers (`SIGTERM`, `SIGINT`) for graceful microservice shutdown.

---

### 2.1.2 User Interfaces
NeuroShell Core provides non-graphical API-first user interfaces:
- **RESTful API Services:** Clean JSON HTTP interfaces exposed via Kong Gateway (`http://localhost:8000/api/*`).
- **OpenAPI Interactive Documentation:** Auto-generated Swagger UI (`/docs`) and ReDoc (`/redoc`) served at each microservice endpoint.
- **Structured JSON Contracts:** Terminal-friendly and agent-parseable JSON input/output schemas.

---

### 2.1.3 Hardware Interfaces
- **Minimum Requirements:**
  - CPU: 8-core x86_64 CPU.
  - RAM: 16 GB system memory.
  - Disk: 20 GB available NVMe storage for container images and log artifacts.
- **Recommended Hardware (for Local LLM GPU Acceleration):**
  - GPU: NVIDIA GPU with at least 16 GB VRAM (e.g., RTX 4090, A100/T4 on cloud).
  - CUDA / Drivers: NVIDIA Container Toolkit configured for Docker GPU passthrough (`nvidia-smi`).

---

### 2.1.4 Software Interfaces
- **Ollama LLM Runtime:** Local Ollama service running on port `11434` serving model `gemma4:e4b` or `gemma4:27b-it`.
- **Kong API Gateway:** Version 3.x declarative API Gateway handling route routing, rate limiting, and CORS.
- **spaCy NLP Library:** `en_core_web_sm` language package used in preprocessing.
- **Pydantic v2 & jsonschema:** Schema validation engine.

---

### 2.1.5 Communication Interfaces
- **Protocols:** HTTP/1.1 and HTTP/2 over TCP/IP.
- **Network Ports:**
  - `8000`: Kong Gateway HTTP Ingress
  - `8443`: Kong Gateway HTTPS Ingress
  - `8001`: Adaptive Execution Error Recovery Service
  - `8002`: AI Vulnerability Analysis Service
  - `8003`: Dynamic Planner RAG Service
  - `8004`: Intent Recognition Engine (IRE) / Proxy Service
  - `11434`: Local Ollama REST API

---

### 2.1.6 Memory Constraints
Individual service memory reservations and resource limits enforced in `infra/docker/prod-compose.yml`:

| Service | Memory Limit | Reserved Memory | CPU Limit | Reserved CPU |
|---|---|---|---|---|
| **Kong Gateway** | 512 MB | 256 MB | 0.5 Cores | 0.25 Cores |
| **Adaptive Error Recovery** | 1024 MB | 512 MB | 1.0 Cores | 0.5 Cores |
| **AI Vulnerability Analysis** | 1024 MB | 512 MB | 1.0 Cores | 0.5 Cores |
| **Dynamic Planner RAG** | 1024 MB | 512 MB | 1.0 Cores | 0.5 Cores |
| **Intent Recognition (IRE)** | 1024 MB | 512 MB | 1.0 Cores | 0.5 Cores |

---

### 2.1.7 Operations
- **Normal Operations:**
  - Microservice start/stop via `docker-compose -f dev-compose.yml up -d`.
  - Health check polling on `/health` endpoints.
  - Natural language parsing on `/api/intent-recognition/parse`.
  - Automated planning and vulnerability scanning requests.
- **Special Operations:**
  - Declarative Kong route reloading via `infra/kong/kong.yml`.
  - Model pulling via `ollama pull gemma4:e4b`.
  - LoRA fine-tuning execution via `neuroshell-ire/scripts/train_lora.py`.

---

### 2.1.8 Site Adaptation Requirements
- **Private Network Binding:** Services must be configured via environment variables (`.env`) to bind to local Docker bridge network `neuroshell-network`.
- **RFC-1918 Restriction:** `ScopeGuard` requires targets to resolve within private IP blocks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or approved staging domains unless explicit override flags are supplied.

---

## 2.2 Product Functions
*Comment: Summary of the major functions of the application.*

1. **7-Stage NLU Command Parsing (NeuroShell IRE):**
   - **Input Normalization:** Strips irregular whitespace, applies Unicode NFKC normalization, standardizes slang (`pwn` $\rightarrow$ `exploit`, `box` $\rightarrow$ `host`).
   - **Alias Resolution:** Converts security aliases (`EternalBlue` $\rightarrow$ `CVE-2017-0144`, `Log4Shell` $\rightarrow$ `CVE-2021-44228`).
   - **Ollama Inference:** Invokes local Gemma 4 model with engineered prompt to generate strict JSON.
   - **JSON Cleanup:** Strips markdown code blocks and `<think>` reasoning tags.
   - **Pydantic Validation:** Enforces `IntentSchema` structural types.
   - **Regex Validation:** Verifies IP/CIDR formats, CVE patterns (`CVE-YYYY-NNNNN`), and sanitizes command metacharacters (`;&|`).
   - **Scope Guarding:** Blocks prompt injection techniques and public IP targeting.

2. **Dynamic Task Planning (Dynamic Planner RAG):**
   - Retrieves security context snippets relevant to natural language goals.
   - Synthesizes ordered multi-step `PlanStep` graphs with action types (`execute`, `query`, `transform`, `aggregate`, `validate`).
   - Evaluates step constraints and computes estimated duration and overall success probability.

3. **AI Vulnerability Scanning & Risk Analysis (AI Vulnerability Analysis):**
   - Audits target models, APIs, prompt templates, and system configurations.
   - Identifies vulnerability categories (`prompt_injection`, `data_poisoning`, `model_dos`, `privacy_leak`).
   - Computes risk score, maps findings to CWE IDs and CVSS scores, and generates actionable remediation recommendations.

4. **Self-Healing Adaptive Recovery (Adaptive Execution Error Recovery):**
   - Classifies runtime execution errors (`timeout`, `resource`, `validation`, `authentication`, `network`).
   - Constructs `RecoveryPlan` with concrete strategies (`retry`, `fallback`, `circuit_breaker`, `queue`, `manual`).
   - Executes automated recovery actions and measures execution latency and outcome status.

5. **API Gateway Orchestration (Kong API Gateway):**
   - Enforces per-IP rate limiting (60 requests/minute per service).
   - Inject headers (`X-Gateway-Version: 1.0`, `X-Service-Name: neuroshell-core`).
   - Provides unified CORS origin handling and TLS encryption termination.

---

## 2.3 User Characteristics
*Comment: Indicate what kind of people the typical user is likely to be.*

- **Red Team Operators & Penetration Testers:** Technical security professionals who want to issue high-level tactical commands in natural language while maintaining complete control over execution safety and structured output contracts.
- **Autonomous Security Agent Developers:** Software engineers building multi-agent security frameworks requiring a reliable, schema-validated NLU parser layer.
- **Cybersecurity Researchers:** Academic and industry researchers investigating AI safety, prompt injection defense, model fine-tuning, and automated vulnerability management.
- **Technical Knowledge Expectation:** Advanced understanding of networking (TCP/IP, CIDR subnets), REST APIs, JSON data formats, and ethical hacking concepts.

---

## 2.4 Constraints
*Comment: All conditions that may limit developer's options.*

1. **Safety Constraints:** Mandatory rejection of unvalidated natural language commands and prompt injection attempts by `ScopeGuard`.
2. **Local AI Execution Constraint:** Microservices must be capable of running offline without reliance on third-party commercial APIs (e.g., OpenAI API), requiring local model execution via Ollama.
3. **Pydantic Schema Strictness:** All service communications must strictly adhere to Pydantic v2 schemas; non-conforming JSON responses trigger HTTP 422 or HTTP 400 validation errors.
4. **Latency Constraints:** Local LLM inference adds 10-15 seconds of latency per natural language parse request.
5. **Python Concurrency Constraint:** Python GIL requires async I/O (`asyncio`, `httpx`) and non-blocking handlers for HTTP proxying.

---

## 2.5 Assumptions and Dependencies
*Comment: Any assumptions being made.*

1. **Host Environment:** Target host has Docker Engine and Docker Compose installed with access to local network ports `8000`-`8004`.
2. **Ollama Availability:** Ollama daemon is running locally or accessible via network on port `11434` with `gemma4:e4b` model pulled.
3. **Authorized Target Network:** Operator possesses explicit authorization to conduct security assessments on targeted IP ranges.
4. **JWT / API Key Provisioning:** Clients include valid `X-API-Key` or `Authorization: Bearer <JWT>` headers when authentication is enabled in production.

---

## 2.6 Apportioning of Requirements
*Comment: Order in which requirements are to be implemented.*

- **Phase 1 (Completed Core Baseline):**
  - Containerized microservices architecture with FastAPI and Poetry.
  - Kong API Gateway setup with declarative routing, rate limiting, and CORS.
  - Initial 7-stage NeuroShell IRE pipeline implementation with base Gemma 4 model.
  - Implementation of models and endpoints for Dynamic Planner, AI Vulnerability Analysis, and Adaptive Recovery.
- **Phase 2 (Current Focus - Model Adaptation & Integration):**
  - Fine-tuning Gemma 4 27B-IT model using synthetic 20,000 example security dataset via LoRA/PEFT on Kaggle/A100.
  - Enhanced RAG context vector storage integration for Dynamic Planner.
  - Integration testing across all microservices using `pytest-asyncio` and `httpx`.
- **Phase 3 (Future Scope):**
  - Web UI Dashboard (`apps/web`) development for visual pipeline execution monitoring.
  - Kubernetes Helm chart deployment manifests for cluster scaling.

---

# 3 Specific Requirements

## 3.1 External Interface Requirements

### 3.1.1 User Interfaces
All endpoints return standard JSON responses wrapped via `APIResponse` or service-specific Pydantic schemas.

#### Primary Gateway Endpoints (Port 8000 via Kong):
- `POST /api/intent-recognition/parse`: Parse natural language into structured `IntentSchema`.
- `POST /api/dynamic-planner-rag/api/v1/plan`: Synthesize execution plan from security goal.
- `POST /api/ai-vulnerability-analysis/api/v1/analyze`: Perform vulnerability analysis on target.
- `POST /api/adaptive-error-recovery/api/v1/process-error`: Formulate recovery plan for runtime error.
- `GET /health`: Aggregate health check status of gateway and all upstream services.

---

### 3.1.2 Hardware Interfaces
- **GPU Passthrough:** NVIDIA Docker container runtime integration for Ollama model inference (`--gpus all` or Docker compose `deploy.resources.reservations.devices`).
- **Disk Storage:** Volume mounts for persistent logs (`/logs`), alias maps (`/data`), and model caches (`/models`).

---

### 3.1.3 Software Interfaces
- **FastAPI Framework:** Version 0.115.0+ handling REST requests asynchronously.
- **Pydantic Data Validation:** Version 2.9.0+ enforcing strict type annotations and serialization.
- **Ollama API Communication:** Async HTTP requests via `httpx` to `http://localhost:11434/api/generate`.
- **Loguru & Structlog:** Structured JSON log formatting.

---

### 3.1.4 Communication Interfaces
- **REST Protocol:** HTTP/1.1 with `Content-Type: application/json`.
- **Custom Gateway Headers:**
  - `X-Gateway-Version`: Ingress gateway version tag (`1.0`).
  - `X-Service-Name`: Target service identification header (`neuroshell-core`).
  - `X-API-Key`: Ingress authentication key header.

---

## 3.2 Classes / Objects
*Comment: This section lists domain classes pertaining to the application organized by requirements.*

Every domain class is categorized by requirement priority: **[Essential]**, **[Desirable]**, or **[Optional]**.

### 1. Intent Recognition Subsystem (IRE)

#### Class: `IntentSchema` [Essential]
- **Description:** Structured representation of parsed operator intent.
- **Attributes:**
  - `intent: IntentCategory` (Enum: `NETWORK_SCAN`, `VULNERABILITY_AUDIT`, `DIRECTORY_BRUTEFORCE`, `SERVICE_ENUMERATION`, `EXPLOITATION`, `PASSWORD_ATTACK`, `PASSIVE_RECON`, `AMBIGUOUS`, `REJECTED`)
  - `target: TargetObject` (Object containing `type` and `value`)
  - `ports: list[int]` (List of explicit target ports)
  - `modifiers: list[str]` (Adverbial modifiers e.g., `stealth`, `aggressive`)
  - `cve_ids: list[str]` (Associated CVE identifiers)
  - `tool_hint: str | None` (Suggested CLI security tool)
  - `schedule: str | None` (Cron expression for scheduled execution)
  - `confidence: float` (Model certainty score, $0.0 \le c \le 1.0$)
  - `rejection_reason: str | None` (Reason for intent rejection)
- **Methods:** `model_dump_json()`, `validate_scope()`

#### Class: `InputNormalizer` [Essential]
- **Description:** Stage 1 pipeline processing component.
- **Methods:** `normalize(raw_text: str) -> str` (Applies NFKC Unicode normalization, strips whitespace, standardizes security slang).

#### Class: `AliasResolver` [Essential]
- **Description:** Stage 2 pipeline component resolving security aliases.
- **Attributes:** `alias_map: dict[str, Any]` (Loaded from `data/alias_map.json`).
- **Methods:** `resolve(text: str) -> tuple[str, list[str]]` (Replaces aliases e.g., `EternalBlue` with `CVE-2017-0144`).

#### Class: `OllamaInference` [Essential]
- **Description:** Stage 3 LLM client communicating with Ollama REST API.
- **Attributes:** `model_name: str`, `base_url: str`, `temperature: float`
- **Methods:** `predict(prompt: str) -> str`

#### Class: `JSONParser` [Essential]
- **Description:** Stage 4 component extracting raw JSON from LLM output.
- **Methods:** `extract_json(llm_output: str) -> dict[str, Any]` (Strips markdown ```json blocks and `<think>` tags).

#### Class: `SchemaValidator` [Essential]
- **Description:** Stage 5 component enforcing Pydantic `IntentSchema`.
- **Methods:** `validate(data: dict[str, Any]) -> IntentSchema`

#### Class: `RegexValidator` [Essential]
- **Description:** Stage 6 component performing deterministic regex checks.
- **Methods:** `validate_patterns(intent: IntentSchema) -> list[str]` (Verifies IPv4/IPv6/CIDR formats and sanitizes dangerous shell characters `;|&`).

#### Class: `ScopeGuard` [Essential]
- **Description:** Stage 7 component enforcing safety and scope boundaries.
- **Methods:** `check_scope(intent: IntentSchema) -> tuple[bool, list[str]]` (Ensures targets belong to RFC-1918 subnets and checks for prompt injection).

---

### 2. Adaptive Execution Error Recovery Subsystem

#### Class: `ErrorDetails` [Essential]
- **Attributes:** `error_type: str`, `message: str`, `stack_trace: str | None`, `severity: ErrorSeverity`, `category: ErrorCategory`, `context: ErrorContext`.

#### Class: `RecoveryPlan` [Essential]
- **Attributes:** `error_id: str`, `selected_strategy: RecoveryStrategy`, `actions: list[RecoveryAction]`, `estimated_time_seconds: float`, `success_probability: float`.

#### Class: `RecoveryAction` [Essential]
- **Attributes:** `action: RecoveryStrategy` (Enum: `RETRY`, `FALLBACK`, `CIRCUIT_BREAKER`, `QUEUE`, `MANUAL`), `description: str`, `parameters: dict[str, Any]`.

---

### 3. AI Vulnerability Analysis Subsystem

#### Class: `VulnerabilityFinding` [Essential]
- **Attributes:** `finding_id: str`, `title: str`, `description: str`, `severity: VulnerabilitySeverity`, `category: VulnerabilityCategory`, `affected_component: str`, `attack_vectors: list[AttackVector]`, `cwe_id: str | None`, `cvss_score: float | None`, `recommendation: str`.

#### Class: `AnalysisReport` [Essential]
- **Attributes:** `report_id: str`, `target: str`, `metadata: AnalysisMetadata`, `vulnerability_count: int`, `critical_count: int`, `high_count: int`, `medium_count: int`, `low_count: int`, `findings: list[VulnerabilityFinding]`, `risk_score: float`.

---

### 4. Dynamic Planner RAG Subsystem

#### Class: `GeneratedPlan` [Essential]
- **Attributes:** `plan_id: str`, `goal: str`, `complexity: PlanComplexity`, `steps: list[PlanStep]`, `constraints: list[PlanConstraint]`, `estimated_duration_seconds: float`, `success_probability: float`.

#### Class: `PlanStep` [Essential]
- **Attributes:** `step_id: str`, `step_number: int`, `action: Action`, `status: str`, `result: dict[str, Any] | None`.

---

### 5. Cross-Cutting & Utility Components

#### Class: `MetricsCollector` [Desirable]
- **Description:** Collects request counts, intent distributions, error counts, and latency percentiles ($p_{50}, p_{95}, p_{99}$).
- **Methods:** `record_request(latency_ms: float, success: bool, intent: str)`

#### Class: `FineTuningAdapter` [Optional]
- **Description:** Module managing LoRA hyperparameter configuration and PEFT weights export.
- **Attributes:** `r: int = 16`, `lora_alpha: int = 32`, `target_modules: list[str]`.

---

## 3.3 Performance Requirements
*Comment: Performance requirements include required speeds, time to complete, and memory usage.*

1. **Pipeline Latency:**
   - Preprocessing (Stages 1, 2, 4, 5, 6, 7): Total execution time $< 50\text{ ms}$.
   - Stage 3 LLM Inference (Local Gemma 4 E4B): Median latency ($p_{50}$) $< 12.0\text{ s}$; 95th percentile ($p_{95}$) $< 25.0\text{ s}$.
2. **Throughput:**
   - Microservice container ingress capacity: Up to 100 concurrent HTTP requests/sec.
   - Kong Gateway rate limit policy: Default 60 requests/minute per client IP.
3. **Memory Footprint (Static & Dynamic):**
   - Idle Container Memory: $\le 150\text{ MB}$ per microservice container.
   - Peak Execution Memory: $\le 1024\text{ MB}$ per microservice container under full payload load.
   - Local Ollama GPU VRAM Usage: $\sim 4.5\text{ GB}$ for Gemma 4 E4B (4-bit quantization) or $\sim 16\text{ GB}$ for Gemma 4 27B-IT.
4. **Accuracy & Precision Metrics:**
   - Intent classification accuracy on 9 intent categories: $> 95\%$.
   - JSON parsing validity (valid syntax post extraction): $> 99.5\%$.
   - False positive scope violation rate: $< 0.1\%$.

---

## 3.4 Design Constraints
*Comment: Restrictions on design.*

1. **Zero Raw Shell Execution:** Microservices must never pass unvalidated natural language input directly to system shell interpreters (`eval()`, `exec()`, or unescaped `subprocess.Popen`).
2. **Strict Schema Enclosure:** Every API request and response MUST inherit from Pydantic `BaseModel` or Pydantic settings.
3. **Stateless Microservices Design:** All 4 application microservices must maintain zero session state on local disk; state must be passed via request parameters or managed via persistent data stores.
4. **Single Ingress Architecture:** External clients must communicate solely through the Kong API Gateway (`Port 8000`), except during direct localized container unit testing.

---

## 3.5 Software System Attributes

### 3.5.1 Reliability
- **Self-Healing Execution:** The Adaptive Execution Error Recovery service automatically evaluates failed execution steps and applies recovery strategies (retry with backoff, circuit breaking).
- **Graceful Failure:** When LLM output fails JSON parsing or schema validation after retries, the pipeline returns a structured error contract (`HTTP 400` / `HTTP 422`) with detailed diagnostic error messages rather than crashing the container process.
- **Container Auto-Restart:** All production containers specify `restart: unless-stopped` in `prod-compose.yml`.

---

### 3.5.2 Availability
- **High Availability Gateway:** Kong API Gateway provides fault-tolerant request proxying and dynamic upstream health checking.
- **Service Health Monitoring:** Docker container healthchecks run every 30 seconds (`curl -f http://localhost:8000/health`), marking unhealthy containers for automatic container engine replacement.
- **Uptime Target:** Designed for $99.9\%$ operational availability in production deployment.

---

### 3.5.3 Security
- **Strict Scope Enforcement (`ScopeGuard`):** Prevents unauthorized scanning of external public IP space by verifying targets against RFC-1918 private subnets.
- **Prompt Injection Defense:** Scans natural language inputs against known prompt injection vectors (e.g., `"ignore all previous instructions"`, `"override system prompt"`), assigning `REJECTED` intent upon detection.
- **API Key & JWT Authentication:** Secured endpoints enforce authentication via standard `X-API-Key` or OAuth2 JWT Bearer tokens.
- **Rate Limiting:** Protects microservices against Denial of Service (DoS) attacks via Kong rate-limiting plugins (60 req/min).

---

### 3.5.4 Maintainability
- **Monorepo Architecture:** Single codebase organized into `/apps`, `/shared`, `/infra`, and `/tests`, allowing shared dependency updates.
- **Automated Code Formatting & Linting:** Codebase enforces strict PEP 8 and Python 3.11 standards via `ruff check` and `black`.
- **Comprehensive Unit & Integration Testing:** Test coverage maintained via `pytest` and `pytest-asyncio` under `/tests` and `neuroshell-ire/tests`.

---

## 3.6 Other Requirements
- **Structured JSON Logging:** All services output JSON logs via `loguru` and `structlog` containing correlation `request_id`, `timestamp`, `service_name`, and execution `latency_ms` for audit trails.
- **OpenAPI Schema Export:** All FastAPI instances export valid OpenAPI 3.0 specifications for automatic client SDK generation.

---

# 4 Supporting Information (Continued)

## 4.2 Appendices

### Appendix A: Alias Map (`data/alias_map.json`) Matrix
The following canonical security mapping table is maintained by `AliasResolver` to resolve informal security slang and vulnerability aliases:

| Alias / Term | Resolved Canonical Identifier | Type |
|---|---|---|
| `EternalBlue` | `CVE-2017-0144` | CVE Identifier |
| `Log4Shell` | `CVE-2021-44228` | CVE Identifier |
| `BlueKeep` | `CVE-2019-0708` | CVE Identifier |
| `ShellShock` | `CVE-2014-6271` | CVE Identifier |
| `Heartbleed` | `CVE-2014-0160` | CVE Identifier |
| `PrintNightmare` | `CVE-2021-34527` | CVE Identifier |
| `ZeroLogon` | `CVE-2020-1472` | CVE Identifier |
| `ProxyLogon` | `CVE-2021-26855` | CVE Identifier |
| `DirtyPipe` | `CVE-2022-0847` | CVE Identifier |
| `PwnKit` | `CVE-2021-4034` | CVE Identifier |
| `pwn` | `exploit` | Slang Standardization |
| `box` | `host` | Slang Standardization |
| `syn scan` | `SYN stealth scan` | Term Normalization |
| `ping sweep` | `ICMP discovery scan` | Term Normalization |
| `brute` | `brute force` | Slang Standardization |
| `enum` | `enumeration` | Slang Standardization |
| `recon` | `reconnaissance` | Slang Standardization |

---

### Appendix B: Key API Endpoint Request/Response Schemas

#### 1. Intent Recognition Engine Parsing Endpoint (`POST /api/intent-recognition/parse` or `POST /parse`)

**Sample Request Payload:**
```json
{
  "command": "Do a stealth ICMP discovery scan of 192.168.1.0/24",
  "session_id": "op-001"
}
```

**Sample 200 OK Response Payload:**
```json
{
  "status": "success",
  "intent": "NETWORK_SCAN",
  "target": {
    "type": "SUBNET",
    "value": "192.168.1.0/24"
  },
  "ports": [],
  "modifiers": [
    "stealth"
  ],
  "cve_ids": [],
  "tool_hint": "nmap",
  "schedule": null,
  "confidence": 0.97,
  "rejection_reason": null,
  "scope_warnings": [],
  "latency_ms": 12450.5
}
```

**Sample Rejected Response (Prompt Injection / Out of Scope):**
```json
{
  "status": "error",
  "error": "SCOPE_VIOLATION",
  "stage": "scope_guard",
  "field": null,
  "detail": "Prompt injection pattern detected in input command",
  "latency_ms": 150.2
}
```

---

#### 2. Adaptive Execution Error Recovery Endpoint (`POST /api/adaptive-error-recovery/api/v1/process-error`)

**Sample Request Payload:**
```json
{
  "error": {
    "error_type": "TimeoutError",
    "message": "Target 10.0.0.5 failed to respond within 30 seconds",
    "severity": "medium",
    "category": "timeout",
    "context": {
      "service_name": "network_scanner",
      "request_id": "req-9921"
    }
  }
}
```

**Sample 200 OK Response Payload:**
```json
{
  "error_id": "err-ae821f92",
  "recovery_plan": {
    "error_id": "err-ae821f92",
    "selected_strategy": "retry",
    "actions": [
      {
        "action": "retry",
        "description": "Retry execution with exponential backoff",
        "parameters": {
          "max_retries": 3,
          "backoff_factor": 2.0
        }
      }
    ],
    "estimated_time_seconds": 10.0,
    "success_probability": 0.85
  },
  "recommended_action": {
    "action": "retry",
    "description": "Retry execution with exponential backoff",
    "parameters": {
      "max_retries": 3,
      "backoff_factor": 2.0
    }
  },
  "can_recover": true,
  "message": "Recovery plan generated successfully"
}
```

---

### Appendix C: Container Resource Deployment Specs

Excerpt from `infra/docker/prod-compose.yml`:
```yaml
version: "3.8"

services:
  kong:
    build:
      context: ../kong
      dockerfile: Dockerfile
    container_name: neuroshell-kong
    ports:
      - "8000:8000"
      - "8443:8443"
    environment:
      KONG_DATABASE: "off"
      KONG_DECLARATIVE_CONFIG: /usr/local/kong/declarative/kong.yml
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 512M

  intent-recognition:
    build:
      context: ../../apps/services/intent-recognition
      dockerfile: Dockerfile
    container_name: neuroshell-intent-recognition
    ports:
      - "8004:8000"
    environment:
      - APP_NAME=intent-recognition
      - ENVIRONMENT=production
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 1024M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

---

# 1.4 References
*Comment: References to all documents that are connected to this one.*

1. **IEEE Std 830-1998:** *IEEE Recommended Practice for Software Requirements Specifications*, IEEE Computer Society, 1998.
2. **RFC 1918:** *Address Allocation for Private Internets*, Network Working Group, Y. Rekhter et al., February 1996.
3. **NIST SP 800-115:** *Technical Guide to Information Security Testing and Assessment*, National Institute of Standards and Technology, 2008.
4. **MITRE ATT&CK Framework:** *Enterprise & Mobile Attack Matrix*, MITRE Corporation, 2024.
5. **OpenAPI Specification v3.0.3:** *OpenAPI Initiative*, Linux Foundation, 2020.
6. **Kong Gateway Declarative Configuration Specification:** *Kong Inc.*, 2024. [https://docs.konghq.com](https://docs.konghq.com)
7. **FastAPI Web Framework Documentation:** *Sebastián Ramírez*, 2024. [https://fastapi.tiangolo.com](https://fastapi.tiangolo.com)
8. **Ollama REST API Reference:** *Ollama Team*, 2024. [https://github.com/ollama/ollama](https://github.com/ollama/ollama)
9. **Pydantic v2 Core Documentation:** *Samuel Colvin et al.*, 2024. [https://docs.pydantic.dev](https://docs.pydantic.dev)
