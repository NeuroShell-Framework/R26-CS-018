# NeuroShell — Demo Run Guide

How to bring the full NeuroShell stack up locally for the live demo:

`apps/web console (:5173)` → **C1 IRE** `:8001` → **C2 Planner/RAG** `:8002` → **C3 AEERE** `:8003` → **C4 AVAE** `:8004`, with **Redis** and **Neo4j** in Docker.

> Runtime model: **local Python venvs** for the four services + Vite dev server for the console.
> Docker is used only for supporting containers (Redis, Neo4j, Kali execution sandbox).

---

## 1. Prerequisites

| Tool | Notes |
|------|-------|
| **Python 3.12** | `py -3.12 --version`. C3/C4 pins require >= 3.11/3.12. |
| **Docker Desktop** | Must be running (Redis, Neo4j, Kali sandbox). |
| **Ollama** | `ollama list` should show the models below. |
| **Node.js 18+** | For the web console (`apps/web`). |

Ollama models required:

| Model | Used by |
|-------|---------|
| `neuroshell-c2-gemma2-final` | C2 command synthesis (fine-tuned) |
| `gemma4:latest` | C1 intent parsing, C3 causal reasoning |

---

## 2. One-time setup

### 2.1 Environment files

Copy each service's `.env.example` to `.env` (values are the local-dev defaults):

```powershell
Copy-Item apps\services\dynamic-planner-rag\.env.example apps\services\dynamic-planner-rag\.env
Copy-Item apps\services\adaptive-execution-error-recovery\.env.example apps\services\adaptive-execution-error-recovery\.env
Copy-Item apps\services\ai-vulnerability-analysis\.env.example apps\services\ai-vulnerability-analysis\.env
```

C1 (`neuroshell-ire`) already ships a working `.env` (chain wired to `:8002`/`:8003`/`:8004`).

The web console needs `apps\web\.env` (Supabase URL/anon key + C1 URL) — it is already present.

### 2.2 Python venvs (Python 3.12)

One venv per service:

```powershell
py -3.12 -m venv apps\services\dynamic-planner-rag\.venv
py -3.12 -m venv apps\services\adaptive-execution-error-recovery\.venv
py -3.12 -m venv apps\services\ai-vulnerability-analysis\.venv

& apps\services\dynamic-planner-rag\.venv\Scripts\python.exe -m pip install -r apps\services\dynamic-planner-rag\requirements.txt
& apps\services\adaptive-execution-error-recovery\.venv\Scripts\python.exe -m pip install -r apps\services\adaptive-execution-error-recovery\requirements.txt
& apps\services\ai-vulnerability-analysis\.venv\Scripts\python.exe -m pip install -r apps\services\ai-vulnerability-analysis\requirements.txt
```

### 2.3 Register the fine-tuned C2 model

The merged GGUF lives in the C2 folder (git-ignored). Build the Ollama model:

```powershell
cd apps\services\dynamic-planner-rag
ollama create neuroshell-c2-gemma2-final -f Modelfile
ollama run neuroshell-c2-gemma2-final "nmap scan 192.168.1.10"
```

### 2.4 Build the C2 knowledge base

```powershell
cd apps\services\dynamic-planner-rag
& .venv\Scripts\python.exe scripts\ingest_docs.py      # -> "Total chunks ingested: 44"
```

### 2.5 Build the Kali execution image (C3 sandbox)

```powershell
cd apps\services\adaptive-execution-error-recovery
docker build -t neuroshell-kali .
```

### 2.6 Web console dependencies

```powershell
npm --prefix apps\web install   # node_modules is git-ignored
```

---

## 3. Run the demo

Everything at once (starts Redis + Neo4j + Kali, then C1–C4 + Web, with health checks):

```powershell
.\neuroshell_run.ps1
```

Or a subset:

```powershell
.\neuroshell_run.ps1 -Service C2        # one service
.\neuroshell_run.ps1 -Service C1,C2     # a list
```

| Target | What it starts |
|--------|----------------|
| `C1`..`C4` | A service (C3 also ensures Kali + Redis; C4 ensures Neo4j) |
| `Web` | Vite console on :5173 |
| `Redis`, `Neo4j`, `Kali` | Supporting Docker containers only |
| `All` (default) | Everything |

Stop everything:

```powershell
.\neuroshell_stop.ps1
```

---

## 4. Endpoints

| Component | URL | Health |
|-----------|-----|--------|
| Web console | http://127.0.0.1:5173 | — |
| C1 IRE | http://127.0.0.1:8001 | `/health` |
| C2 Planner/RAG | http://127.0.0.1:8002 | `/health` |
| C3 AEERE | http://127.0.0.1:8003 | `/health` |
| C4 AVAE | http://127.0.0.1:8004 | `/health` |
| Neo4j Browser | http://127.0.0.1:7474 | user `neo4j` / pass `neuroshell2026` |

Quick health check (all should return 200):

```powershell
8001,8002,8003,8004 | ForEach-Object {
  (Invoke-WebRequest "http://127.0.0.1:$_/health" -UseBasicParsing).StatusCode
}
```

---

## 5. Demo flow (what to show)

1. Open http://127.0.0.1:5173 and sign in (Supabase auth).
2. Submit a natural-language command, e.g. `nmap scan 192.168.1.10`
   (targets inside the declared scope `192.168.0.0/16`).
3. Walk the chain:
   - **C1** parses intent → structured contract (`NETWORK_SCAN`, target, tool).
   - **C2** produces the validated command (e.g. `nmap -sS -T4 192.168.1.10`).
   - **C3** executes it inside the Kali sandbox and streams stdout.
   - **C4** parses the output, enriches, scores risk, and shows ranked findings.
4. Show persistence in Neo4j Browser:
   ```cypher
   MATCH (n) RETURN n LIMIT 50
   ```
   Expect `Session`, `Host`, and `Service` nodes from the run.

### Direct end-to-end check (bypasses the UI)

```powershell
$body = @{ command = "nmap scan 192.168.1.10"; session_id = "demo"; role = "analyst" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:8001/execute" -Method Post `
  -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 6
```

> Note: C1 caches successful chains per command string. Repeat the **exact** same
> command and you get the cached result; vary the wording to force a fresh run.

---

## 6. Verify the tuned C2 model

```powershell
cd apps\services\dynamic-planner-rag
$env:EVAL_OLLAMA_MODEL = "neuroshell-c2-gemma2-final"
& .venv\Scripts\python.exe scripts\verify_tuned_c2_model.py
```

Reports tool correctness, exact-match, `CommandValidator` and `SafetyFilter`
results for one training and one held-out sample.

---

## 7. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `kb_chunks: 0` in C2 `/health` | Run step 2.4 (re-ingest), then restart C2. |
| C2 `422` with `VALIDATION_FAILED` | The model emitted a malformed command; ensure the KB is ingested and the requested tool is nmap/nikto/gobuster. |
| C4 `/health` returns 404 on an old build | C4 now exposes `/health`; restart C4. |
| Neo4j empty | Confirm `neuroshell-neo4j` is Up and C4 logged `Neo4j connected.` |
| C3 `docker: true` false in `/health` | Docker Desktop not running, or `KALI_IMAGE` not built (step 2.5). |
| Port already in use | `.\neuroshell_stop.ps1` then re-run; check for stray `python`/`node` processes. |

---

## 8. Docker-only (optional)

Each service also has an API Dockerfile for containerized runs:

- `dynamic-planner-rag/Dockerfile` (C2, :8002)
- `adaptive-execution-error-recovery/Dockerfile.api` (C3 API, :8003) — `Dockerfile` is the Kali tool image, `Dockerfile.kali` the nginx target.
- `ai-vulnerability-analysis/Dockerfile` (C4, :8004)

These expect `OLLAMA_HOST`/`OLLAMA_URL=http://host.docker.internal:11434` and a host Redis/Neo4j (or the `infra/docker` compose network).
