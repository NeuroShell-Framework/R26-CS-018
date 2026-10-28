# NeuroShell Lookbook — H1 2026 (Jun 15 – Jul 15)

> **Autonomous, Safe, Explainable Offensive Security Pipeline**  
> From natural language → validated findings in one chain.

---

## 1. Executive Summary

**NeuroShell** is a 4-service microservice pipeline that converts natural-language offensive security commands into validated, executed, and triaged findings — with safety guards, RBAC, and full audit trail at every step.

| Metric | Value |
|--------|-------|
| **Services** | 4 (C1 IRE, C2 Planner/RAG, C3 AEERE, C4 AVAE) |
| **Test Suite** | 30 cases | **24/30 PASS (80%)** baseline → **6/6 PASS** post-fixes |
| **Latency** | Subnet /24: 5.5s | Nikto web scan: ~45s | Full chain avg: 30–90s |
| **Deployment** | Docker Compose, air-gapped ready, Ollama local LLM |

---

## 2. Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   C1 IRE    │────▶│  C2 Planner │────▶│  C3 AEERE   │────▶│  C4 AVAE    │
│  (Port 8001)│     │  (Port 8002)│     │  (Port 8003)│     │  (Port 8004)│
│  Intent     │     │  RAG +      │     │  Kali       │     │  ML Triage  │
│  Recognition│     │  Tool Select│     │  Executor   │     │  + Enrichment│
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
  Validation         Tool + Flag         Kali Container       XGBoost +
  + Scope Guard      Synthesis           + Recovery          NVD/KEV/EPSS
  + RBAC             + Validation                                  Enrichment
```

**Ports:** 8001 (C1) → 8002 (C2) → 8003 (C3) → 8004 (C4) + Web UI 5173

---

## 3. Service Breakdown

### C1 — Intent Recognition Engine (IRE) — Port 8001
- **Tech**: FastAPI, Ollama (gemma2), Redis session store
- **Input**: Natural language (`"scan 192.168.1.10 for open ports"`)
- **Output**: Structured intent contract (v1 + v2 schemas)
- **Validators**: Schema, Regex, Network (RFC-1918), Scope Guard, RBAC, Semantic Cache
- **Key Files**: `src/pipeline/ire_pipeline.py`, `src/validation/*.py`

### C2 — Dynamic Planner & RAG — Port 8002
- **Tech**: FastAPI, ChromaDB (Chroma), SentenceTransformers, Ollama (gemma2)
- **KB**: nmap, nikto, gobuster, whois, dig docs (vector retrieval)
- **Flow**: Intent → Query → Retrieve → Assemble Prompt → Synthesize → Validate
- **Tools**: nmap, nikto, gobuster, **whois**, **dig** (added H1)
- **Key Files**: `src/synthesis/*.py`, `src/validation/*.py`, `scripts/cli_ast_validator.py`

### C3 — Adaptive Execution Error Recovery (AEERE) — Port 8003
- **Tech**: FastAPI, Docker SDK, Kali Linux container (`neuroshell-kali`)
- **Features**: Lab network auto-provision, wall-time guard (120s), silent-failure detection, command recovery/mutation
- **Target**: `neuroshell-lab-target` (nginx + baked vuln files)
- **Key Files**: `src/execution/command_runner.py`, `src/execution/silent_failure_detector.py`, `Dockerfile.kali`

### C4 — AI Vulnerability Analysis (AVAE) — Port 8004
- **Tech**: FastAPI, XGBoost, NVD/KEV/EPSS clients, Neo4j graph
- **Parsers**: nmap, nikto, gobuster (nikto plain-text parser added H1)
- **ML**: Exploitability predictor + Service risk fallback + Triage engine
- **Output**: Ranked findings with CVE, EPSS, KEV, CWE, risk tier, evidence
- **Key Files**: `src/parsers/nikto_parser.py`, `src/api/main.py`, `src/triage/triage_engine.py`

---

## 4. H1 2026 Key Achievements (Jun 15 – Jul 15)

### ✅ Vulnerability Detection Demo (Priority #1)
- **Baked 7 vuln files** into target image: `.env`, `backup.sql`, `config.bak`, `db_backup.sql`, `passwords.txt`, `search.html` (XSS), `robots.txt`
- **C4 nikto parser** extracts 5 paths from plain-text output → ranked as MEDIUM findings
- **Demo command**: `"check for web vulnerabilities on 192.168.1.10 with nikto"` → **6 findings** (5 NIKTO + 1 service-based)

### ✅ PASSIVE_RECON Support (C2)
- Added **whois** & **dig** to tool map, selector, validator, KB
- FC-012 (`whois 192.168.1.10`) & FC-013 (`dig 10.0.0.5 AAAA`) now PASS

### ✅ C3 Reliability Fixes
- **Wall-time guard** (120s max) → /24 sweeps from 360s → **5.5s**
- **Lab network auto-provision** → gobuster now reaches target (fixed bridge networking)

### ✅ Test Suite Progress
| Case | Command | Status |
|------|---------|--------|
| FC-009 | `run a directory brute force on 192.168.1.10 with gobuster` | PASS (admin) |
| FC-010 | `scan the subnet 192.168.1.0/24 for live hosts` | PASS (5.5s) |
| FC-011 | `do a ping sweep of 192.168.1.0/24` | PASS (5.5s) |
| FC-012 | `look up whois information for 192.168.1.10` | PASS |
| FC-013 | `query DNS records for 10.0.0.5` | PASS |
| FC-017 | `scan 8.8.8.8 for open ports` | BLOCKED at C2 ✅ |

**Baseline (pre-fixes)**: 24/30 PASS (80%) → **Post-fixes**: 6/6 targeted PASS (100%)

---

## 5. Safety & Compliance

| Layer | Mechanism |
|-------|-----------|
| **C1 Scope Guard** | RFC-1918 + declared CIDR (192.168.0.0/16) → blocks 8.8.8.8 |
| **C1 RBAC** | `analyst` denied `DIRECTORY_BRUTEFORCE`; `admin` allowed |
| **C2 Safety Filter** | Target validation, allowed tools list, blocked patterns |
| **C2 Validator** | Tool syntax, target position, flag requirements, port format |
| **C3 Isolation** | Ephemeral Kali containers, no host access, privileged=false |
| **Audit Trail** | Chain cache (disk) + per-step latency + full flow JSON |

---

## 6. Demo Commands (Board-Ready)

| # | Command | Time | Highlight |
|---|---------|------|-----------|
| 1 | `scan 8.8.8.8 for open ports` | 3s | Scope block at C2 |
| 2 | `look up whois information for 192.168.1.10` | 15s | Passive recon (whois) |
| 3 | `query DNS records for 10.0.0.5` | 12s | Passive recon (dig) |
| 4 | `scan the subnet 192.168.1.0/24 for live hosts` | 5s | Wall-time guard |
| 5 | `do a service version detection scan on 192.168.1.10` | 20s | Service enum |
| 6 | `check for web vulnerabilities on 192.168.1.10 with nikto` | 45s | **6 findings** |
| 7 | `run a directory brute force on 192.168.1.10 with gobuster` | 27s | RBAC (admin) |

**Clear cache between each**: `.\clear_demo_cache.ps1`

---

## 7. Deployment & Operations

### One-Command Start
```powershell
.\neuroshell_run.ps1          # Starts C1–C4 + Web + Docker (Kali, Redis, Neo4j)
```

### Health Checks
```bash
curl http://127.0.0.1:8001/health  # C1
curl http://127.0.0.1:8002/health  # C2
curl http://127.0.0.1:8003/health  # C3
curl http://127.0.0.1:8004/health  # C4
```

### Air-Gapped Ready
- Ollama local (gemma2)
- ChromaDB local
- Neo4j local
- No external API calls (NVD/KEV/EPSS cached offline)

---

## 8. File Map (Key Paths)

```
F:\neuroshell-core\
├── neuroshell_run.ps1              # Start all services
├── clear_demo_cache.ps1            # Fresh pipeline per demo
├── apps\services\
│   ├── neuroshell-ire\             # C1
│   │   ├── src\api\main.py         # Chain orchestration
│   │   ├── src\integration\        # C2/C3/C4 clients
│   │   └── .env                    # PLANNER_API_KEY
│   ├── dynamic-planner-rag\        # C2
│   │   ├── src\synthesis\          # Tool selection, synthesis
│   │   ├── src\validation\         # AST validator
│   │   ├── data\tool_map.json      # Intent→Tool mapping
│   │   └── .env                    # API_KEY
│   ├── adaptive-execution-error-recovery\  # C3
│   │   ├── src\execution\command_runner.py
│   │   ├── Dockerfile.kali         # Target image (vuln files baked)
│   │   └── vuln_files\             # 7 demo vuln files
│   └── ai-vulnerability-analysis\  # C4
│       ├── src\parsers\nikto_parser.py
│       ├── src\api\main.py         # ML triage + enrichment
├── tests\full_chain\               # 30-case eval suite
└── LOOKBOOK_2026_H1.md             # This file
```

---

## 9. Next Steps (Post H1)

| Priority | Item |
|----------|------|
| 1 | Run full 30-case suite → target 30/30 PASS |
| 2 | C4: Add gobuster/nmap parsers for finding extraction |
| 3 | Web UI: Real-time chain visualization (SSE) |
| 4 | Kubernetes deployment manifests (Helm) |
| 5 | SARIF export for ticketing integration |

---

## 10. Contacts & Repo

- **Repo**: `feature/tharindu` branch (commit `e01f5ab`)
- **Demo Script**: See `DEMO_SCRIPT.md` (separate)
- **Clear Cache**: `.\clear_demo_cache.ps1` before each command

---

*Generated 2026-07-15 | NeuroShell Team*