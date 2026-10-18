"""
Real-model 3-microstep feasibility benchmark for google/gemma-2-2b-it CPU LoRA fine-tuning.
Strictly uses google/gemma-2-2b-it without fallbacks.
Measures actual RAM, CPU utilization, microstep execution time, and extrapolates full training duration.
"""

import os
import sys
import time
import json
import gc
import subprocess
import pandas as pd
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import LoraConfig, get_peft_model

print("=== REAL-MODEL 3-MICROSTEP FEASIBILITY BENCHMARK ===")
print("Interpreter:", sys.executable)
print("PyTorch Version:", torch.__version__)

MODEL_ID = "google/gemma-2-2b-it"
print(f"Target Model: {MODEL_ID} (Strict mode - no fallback repository permitted)")

def get_free_ram_mb():
    try:
        out = subprocess.check_output("wmic os get FreePhysicalMemory /Value", shell=True).decode()
        for line in out.splitlines():
            if "FreePhysicalMemory=" in line:
                return float(line.split("=")[1].strip()) / 1024.0
    except Exception:
        pass
    return -1.0

# 1. RAM Before Load
ram_before_mb = get_free_ram_mb()
print(f"RAM Available Before Load: {ram_before_mb:.2f} MB (~{ram_before_mb/1024.0:.2f} GB)")

# Check HF Token
hf_token = os.getenv("HF_TOKEN") or os.getenv("HUGGING_FACE_HUB_TOKEN")
if not hf_token:
    # Try reading token from Hugging Face hub token cache file if present
    cache_token_path = os.path.expanduser("~/.cache/huggingface/token")
    if os.path.exists(cache_token_path):
        with open(cache_token_path, "r", encoding="utf-8") as f:
            hf_token = f.read().strip()
        print("Loaded HF_TOKEN from ~/.cache/huggingface/token")

if not hf_token:
    print("WARNING: HF_TOKEN is not set in environment or cache file.")

try:
    print(f"\n1. Downloading/Loading Tokenizer for {MODEL_ID}...")
    tokenizer_start = time.time()
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, token=hf_token)
    tokenizer.pad_token = tokenizer.eos_token
    print(f"Tokenizer loaded successfully in {time.time() - tokenizer_start:.2f}s")

    print(f"\n2. Downloading/Loading Base Model {MODEL_ID} (torch.bfloat16 on CPU)...")
    model_start = time.time()
    base_model = AutoModelForCausalLM.from_pretrained(
        MODEL_ID,
        torch_dtype=torch.bfloat16 if hasattr(torch, 'bfloat16') else torch.float32,
        device_map="cpu",
        token=hf_token
    )
    print(f"Base Model loaded successfully in {time.time() - model_start:.2f}s")

except Exception as e:
    print(f"\n[CRITICAL ERROR] Failed to access or load {MODEL_ID}:")
    print(str(e))
    print("\nStopping benchmark as requested when google/gemma-2-2b-it cannot be loaded.")
    sys.exit(1)

ram_after_base_mb = get_free_ram_mb()
print(f"RAM Available After Base Model Load: {ram_after_base_mb:.2f} MB (~{ram_after_base_mb/1024.0:.2f} GB)")
if ram_before_mb > 0 and ram_after_base_mb > 0:
    print(f"Base Model Weight RAM Consumption: {ram_before_mb - ram_after_base_mb:.2f} MB (~{(ram_before_mb - ram_after_base_mb)/1024.0:.2f} GB)")

print("\n3. Applying LoRA Configuration (q_proj, v_proj, r=16, alpha=32)...")
lora_config = LoraConfig(
    r=16,
    lora_alpha=32,
    target_modules=["q_proj", "v_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM"
)

model = get_peft_model(base_model, lora_config)
model.print_trainable_parameters()

ram_after_lora_mb = get_free_ram_mb()
print(f"RAM Available After LoRA Wrapping: {ram_after_lora_mb:.2f} MB (~{ram_after_lora_mb/1024.0:.2f} GB)")

# Load 3 real training examples
df_train = pd.read_csv("data/synthesis_dataset/final/c2_sft_train.csv")
sample_rows = df_train.head(3)

samples = []
for _, r in sample_rows.iterrows():
    text = (
        "<start_of_turn>user\n"
        "Synthesize a valid Kali Linux C2 execution command for the following specification. Output ONLY the executable command.\n\n"
        f"Intent: {r['intent']}\n"
        f"Target: {r['target']}\n"
        f"Ports: {r['ports']}\n"
        f"Modifiers: {r['modifiers']}\n"
        f"Tool: {r['tool']}\n"
        f"Instruction: {r['prompt']}<end_of_turn>\n"
        "<start_of_turn>model\n"
        f"{r['expected_command']}<end_of_turn>"
    )
    samples.append(text)

optimizer = torch.optim.AdamW(model.parameters(), lr=2e-4)

print("\n4. Executing EXACTLY 3 Real Forward/Backward Microsteps...")
microstep_times = []
lowest_free_ram_mb = ram_after_lora_mb

for idx, sample in enumerate(samples):
    step_start = time.time()
    
    # Tokenize input
    inputs = tokenizer(sample, return_tensors="pt", truncation=True, max_length=384)
    input_ids = inputs["input_ids"]
    labels = input_ids.clone()
    
    optimizer.zero_grad()
    
    # Forward pass
    outputs = model(input_ids=input_ids, labels=labels)
    loss = outputs.loss
    
    # Backward pass
    loss.backward()
    optimizer.step()
    
    step_duration = time.time() - step_start
    microstep_times.append(step_duration)
    
    current_free_ram = get_free_ram_mb()
    if current_free_ram > 0 and current_free_ram < lowest_free_ram_mb:
        lowest_free_ram_mb = current_free_ram
        
    print(f"  Microstep {idx+1}/3: Loss = {loss.item():.4f} | Time = {step_duration:.3f}s | Free RAM = {current_free_ram:.2f} MB")

avg_microstep_time = sum(microstep_times) / len(microstep_times)
total_microsteps = 2025  # 675 samples * 3 epochs
extrapolated_seconds = total_microsteps * avg_microstep_time
extrapolated_minutes = extrapolated_seconds / 60.0
extrapolated_hours = extrapolated_seconds / 3600.0

print("\n================ REAL-MODEL BENCHMARK RESULTS SUMMARY ================")
print(f"Interpreter Path:                 {sys.executable}")
print(f"Evaluated Base Model Architecture:{MODEL_ID}")
print(f"Microstep 1 Wall-Clock Duration:  {microstep_times[0]:.3f} seconds")
print(f"Microstep 2 Wall-Clock Duration:  {microstep_times[1]:.3f} seconds")
print(f"Microstep 3 Wall-Clock Duration:  {microstep_times[2]:.3f} seconds")
print(f"Average Microstep Duration:       {avg_microstep_time:.3f} seconds")
print(f"Total Extrapolated 2,025 Steps:   {extrapolated_seconds:.1f}s ({extrapolated_minutes:.2f} minutes / {extrapolated_hours:.2f} hours)")
print(f"RAM Available Before Load:        {ram_before_mb:.2f} MB (~{ram_before_mb/1024.0:.2f} GB)")
print(f"RAM Available After Model Load:   {ram_after_base_mb:.2f} MB (~{ram_after_base_mb/1024.0:.2f} GB)")
print(f"Lowest RAM Available During Step: {lowest_free_ram_mb:.2f} MB (~{lowest_free_ram_mb/1024.0:.2f} GB)")
print(f"Peak RAM Consumption:             {ram_before_mb - lowest_free_ram_mb:.2f} MB (~{(ram_before_mb - lowest_free_ram_mb)/1024.0:.2f} GB)")
print("=====================================================================")

# Clean up memory immediately
del model, base_model, tokenizer
gc.collect()
print("\nBenchmark completed cleanly. NO adapter weights saved. NO .env modified.")
