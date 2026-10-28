"""
NeuroShell IRE — Development Launcher

One-command dev environment setup and server launcher.
Performs prerequisite checks, ensures model is available,
then starts the uvicorn development server with hot-reload.

Usage:
    python scripts/run_dev.py
"""
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

print("=" * 55)
print("  NeuroShell IRE — Intent Recognition Engine")
print("  Component 01 | Research Build")
print("=" * 55)
print()

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)

# --- Step 1: Python version check ---
print("[1/6] Checking Python version...")
if sys.version_info < (3, 11):
    print(f"  WARNING: Python {sys.version_info.major}.{sys.version_info.minor} detected.")
    print("  Recommended: Python 3.11+ for full compatibility.")
    print("  Some dependencies may not work correctly on older versions.")
else:
    print(f"  OK: Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")

# --- Step 2: .env file ---
print("\n[2/6] Checking .env file...")
env_path = ROOT / ".env"
if not env_path.exists():
    example_path = ROOT / ".env.example"
    if example_path.exists():
        shutil.copy(str(example_path), str(env_path))
        print("  Created .env from .env.example")
        print("  REMINDER: Edit .env to configure API key and model settings")
    else:
        print("  WARNING: Neither .env nor .env.example found")
        print("  Set environment variables manually before starting")
else:
    print("  OK: .env file exists")

# --- Step 3: Ollama connectivity ---
ollama_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
print(f"\n[3/6] Checking Ollama at {ollama_url}...")
try:
    import httpx
    r = httpx.get(f"{ollama_url}/api/tags", timeout=3.0)
    if r.status_code == 200:
        print("  OK: Ollama is reachable")
    else:
        print(f"  ERROR: Ollama returned status {r.status_code}")
        print("  Ensure Ollama is running: ollama serve")
        sys.exit(1)
except Exception as e:
    print(f"  ERROR: Cannot reach Ollama at {ollama_url}")
    print(f"  Details: {e}")
    print()
    print("  To fix:")
    print("  1. Install Ollama: https://ollama.ai")
    print("  2. Start the service: ollama serve")
    print("  3. Verify: curl http://localhost:11434/api/tags")
    sys.exit(1)

# --- Step 4: Model availability ---
model = os.environ.get("OLLAMA_MODEL", "gemma4:e4b")
print(f"\n[4/6] Checking model: {model}...")
try:
    import ollama
    models = ollama.list()
    model_names = []
    for m in models.get("models", []):
        model_names.append(m.get("name", ""))
    # Also check the older API response format
    if isinstance(models, dict):
        for m in models.get("models", []):
            if isinstance(m, dict):
                model_names.append(m.get("name", ""))

    found = any(model in name or name in model for name in model_names)
    if found:
        print(f"  OK: {model} is available")
    else:
        print(f"  ERROR: Model '{model}' not found in Ollama")
        print(f"  Available models: {', '.join(model_names) if model_names else 'none'}")
        print()
        print(f"  To fix:  ollama pull {model}")
        sys.exit(1)
except Exception as e:
    print(f"  ERROR: Could not check model availability: {e}")
    print(f"  Please manually verify: ollama pull {model}")

# --- Step 5: spaCy model ---
print("\n[5/6] Checking spaCy model (en_core_web_sm)...")
try:
    import spacy
    spacy.load("en_core_web_sm")
    print("  OK: en_core_web_sm loaded")
except OSError:
    print("  Installing en_core_web_sm...")
    subprocess.run([sys.executable, "-m", "spacy", "download", "en_core_web_sm"], check=True)
    print("  OK: en_core_web_sm installed")

# --- Step 6: Launch server ---
print("\n[6/6] Starting uvicorn development server...")
print("  URL: http://localhost:8001")
print("  Docs: http://localhost:8001/docs")
print("  Health: http://localhost:8001/health")
print()
print("  Press Ctrl+C to stop")
print("=" * 55)
print()

subprocess.run([
    sys.executable, "-m", "uvicorn", "src.api.main:app",
    "--host", "0.0.0.0",
    "--port", "8001",
    "--reload",
    "--log-level", "info"
])
