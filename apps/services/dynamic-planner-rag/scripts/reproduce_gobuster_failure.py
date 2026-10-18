import json
import os
import sys
import ollama
from fastapi.testclient import TestClient

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath("."))

from src.api.main import app, API_KEY, retriever, constructor, interpreter, assembler, synthesizer, validator, safety, session_mgr

captured = {
    "prompt": None,
    "messages": None,
    "model": None,
    "raw_response": None,
    "options": None
}

orig_chat = ollama.chat

def capturing_chat(*args, **kwargs):
    captured["model"] = kwargs.get("model")
    captured["messages"] = kwargs.get("messages")
    captured["options"] = kwargs.get("options")
    # Extract the user prompt from messages
    for msg in kwargs.get("messages", []):
        if msg.get("role") == "user":
            captured["prompt"] = msg.get("content")
    
    res = orig_chat(*args, **kwargs)
    captured["raw_response"] = res["message"]["content"]
    return res

ollama.chat = capturing_chat

def reproduce():
    client = TestClient(app)

    payload = {
        "session_id": "reproduce-gobuster-50",
        "intent": "DIRECTORY_BRUTEFORCE",
        "target_value": "http://192.168.1.50",
        "target_type": "URL",
        "ports": [80],
        "primary_tool": "gobuster",
        "tool_parameters": {
            "wordlist": "common.txt"
        }
    }

    # Also inspect intermediate steps directly
    from src.schemas.models import IREIntentContract
    contract = IREIntentContract(
        intent=payload["intent"],
        target_value=payload["target_value"],
        target_type=payload["target_type"],
        ports=payload["ports"],
        primary_tool=payload["primary_tool"],
        tool_parameters=payload["tool_parameters"]
    )
    
    params = interpreter.interpret(contract)
    query = constructor.build_query(params)
    docs = retriever.retrieve(query, tool_hint=params.get("tool_hint"), top_k=3)
    assembled_prompt = assembler.assemble(docs, params)

    print("=== STEP 1: INTERPRETED PARAMS ===")
    print(json.dumps(params, indent=2))

    print("\n=== STEP 2: CONSTRUCTED QUERY ===")
    print(query)

    print("\n=== STEP 3: RETRIEVED CONTEXT (CHUNKS) ===")
    for i, d in enumerate(docs):
        print(f"--- Doc {i+1} (Tool: {d['tool']}, Score: {d['score']}) ---")
        print(d["content"])

    print("\n=== STEP 4: ASSEMBLED PROMPT ===")
    print(assembled_prompt)

    print("\n=== STEP 5: RUNNING API REQUEST POST /plan ===")
    response = client.post("/plan", json=payload, headers={"x-api-key": API_KEY})

    print("\n=== STEP 6: CAPTURED OLLAMA INVOCATION ===")
    print(f"Model used: {captured['model']}")
    print(f"Raw Ollama output:\n{captured['raw_response']}")

    print("\n=== STEP 7: API RESPONSE ===")
    print(f"Status Code: {response.status_code}")
    print(f"Response Body:\n{json.dumps(response.json(), indent=2)}")

if __name__ == "__main__":
    reproduce()
