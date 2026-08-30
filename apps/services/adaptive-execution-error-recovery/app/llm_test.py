import time
import ollama
start = time.time()
response = ollama.chat(
    model='qwen2.5-coder:latest',
    messages=[
        {'role': 'system', 'content': 'You are a Kali Linux command correction expert. Output ONLY the corrected bash command as a single line of raw text.'},
        {'role': 'user', 'content': 'Failed Command: nikto --invalid-option-xyz -h 192.168.1.10\nError Class: WRONG_SYNTAX\nOutput ONLY the corrected command:'}
    ],
    options={'temperature': 0.05, 'num_predict': 100},
    keep_alive='30m'
)
elapsed = time.time() - start
print(f'LLM call took: {elapsed:.2f} seconds')
print(f'Response: {response["message"]["content"]}')
