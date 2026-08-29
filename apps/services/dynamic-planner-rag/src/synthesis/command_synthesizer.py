import os
import ollama
from dotenv import load_dotenv
from typing import List, Dict

# Load environment variables
load_dotenv()
MODEL_NAME = os.getenv("OLLAMA_MODEL", "gemma4:e4b")


class CommandSynthesizer:
    """Accepts a fully-assembled prompt, interpreted params, and retrieved docs
    from main.py and calls Ollama directly. The RAG pipeline is NOT run here;
    it is orchestrated once by main.py to avoid double-processing.
    """

    def __init__(self):
        print("CommandSynthesizer initialized")

    def parse_command_output(self, raw_content: str, multi_step: bool = False) -> List[str]:
        """Parses and cleans raw LLM output into an ordered list of command strings.
        
        Handles:
          - Markdown code blocks (```bash ... ```)
          - Numbered command lines ("1. nmap ...", "2) nikto ...", "[1] gobuster ...")
          - Bullet points ("- nmap ...", "* nikto ...", "• gobuster ...")
          - Leading shell prompt symbols ("$ nmap ...", "# nikto ...")
          - Surrounding explanation/header commentary lines.
        """
        import re

        content = raw_content.strip()
        content = content.replace("```bash", "").replace("```sh", "").replace("```", "").strip()

        lines = content.split("\n")
        commands = []

        for line in lines:
            cleaned = line.strip()
            if not cleaned:
                continue

            # Strip leading numbers, bullets, or prompt symbols
            cleaned = re.sub(r'^(?:\d+[\.\)]|\*|-|•|\[\d+\])\s*', '', cleaned)
            cleaned = re.sub(r'^[#\$]\s*', '', cleaned).strip()

            # Filter out obvious non-command commentary lines
            lower = cleaned.lower()
            if lower.startswith(("here is", "note:", "step ", "command:", "command sequence:", "explanation:", "summary:", "the following")):
                continue

            if cleaned:
                commands.append(cleaned)

        if not commands:
            commands = [raw_content.strip()]

        if not multi_step:
            return [commands[0]]

        # Defensive limit (max 5 commands)
        return commands[:5]

    def synthesize(self, prompt: str, params: dict, docs: List[Dict]) -> dict:
        """Synthesize a command using Ollama.

        Args:
            prompt:  The fully-assembled LLM prompt (built by ContextAssembler
                     in main.py, with target-reinforcement already appended).
            params:  The interpreted params dict from IntentInterpreter.
                     May contain '_query_used' for pass-through logging.
            docs:    The retrieved RAG documents from VectorRetriever.

        Returns:
            dict with keys: command, command_sequence, retrieval_sources, query_used
        """
        # Collect sources from the pre-retrieved docs
        sources = [d.get("source", d.get("tool", "unknown")) for d in docs]

        # Call Ollama with the pre-built prompt
        response = ollama.chat(
            model=MODEL_NAME,
            messages=[
                {
                    "role": "system",
                    "content": "You are a Kali Linux command generator. Output ONLY valid commands. Do not explain."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        raw_output = response["message"]["content"].strip()
        multi_step = bool(params.get("multi_step", False))
        command_seq = self.parse_command_output(raw_output, multi_step=multi_step)
        primary_command = command_seq[0] if command_seq else raw_output

        return {
            "command": primary_command,
            "command_sequence": command_seq,
            "retrieval_sources": sources,
            "query_used": params.get("_query_used", ""),
        }


# ================= STANDALONE TEST RUN =================
# Manually rebuilds the pipeline steps that main.py normally orchestrates.
if __name__ == "__main__":
    from src.schemas.models import IREIntentContract
    from src.intent.intent_interpreter import IntentInterpreter
    from src.intent.query_constructor import QueryConstructor
    from src.rag.vector_retriever import VectorRetriever
    from src.rag.context_assembler import ContextAssembler

    contract = IREIntentContract(
        intent     ="NETWORK_SCAN",
        target     ={"type": "IP", "value": "192.168.1.1"},
        ports      =[],
        modifiers  =["stealth"],
        cve_ids    =[],
        tool_hint  ="nmap",
        confidence =0.97
    )

    # Rebuild pipeline steps locally for standalone use
    _interpreter = IntentInterpreter()
    _constructor = QueryConstructor()
    _retriever   = VectorRetriever()
    _assembler   = ContextAssembler()

    _params  = _interpreter.interpret(contract)
    _query   = _constructor.build_query(_params)
    _docs    = _retriever.retrieve(_query, tool_hint=_params.get("tool_hint"), top_k=3)
    _prompt  = _assembler.assemble(_docs, _params)
    _prompt += (
        f"\n\nIMPORTANT:\n"
        f"Use this exact target in the command: {_params['target_value']}\n"
        f"Output ONLY one command.\n"
    )
    _params["_query_used"] = _query

    synthesizer = CommandSynthesizer()
    result      = synthesizer.synthesize(_prompt, _params, _docs)

    print("\nGenerated Command:", result["command"])
    print("Sources:", result["retrieval_sources"])