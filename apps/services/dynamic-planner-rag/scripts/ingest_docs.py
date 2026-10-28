import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["ANONYMIZED_TELEMETRY"] = "False"
os.environ["CHROMA_TELEMETRY"] = "False"

import chromadb
from sentence_transformers import SentenceTransformer
from dotenv import load_dotenv

load_dotenv()

RAW_DOCS_DIR = os.path.join(os.path.dirname(__file__), '..', 'knowledge_base', 'raw_docs')
CHROMA_DIR   = os.path.join(os.path.dirname(__file__), '..', 'knowledge_base', 'chroma_db')

def chunk_text(text, chunk_size=80, overlap=20):
    words  = text.split()
    chunks = []
    i      = 0
    while i < len(words):
        chunk = ' '.join(words[i:i+chunk_size])
        chunks.append(chunk)
        i += chunk_size - overlap
    return chunks

def ingest():
    print("Starting knowledge base ingestion...")

    client     = chromadb.PersistentClient(path=CHROMA_DIR)
    model      = SentenceTransformer('all-MiniLM-L6-v2')
    collection = client.get_or_create_collection(
        name="tool_documentation",
        metadata={"hnsw:space": "cosine"}
    )

    txt_files = [f for f in os.listdir(RAW_DOCS_DIR) if f.endswith('.txt')]
    
    if not txt_files:
        print("No .txt files found in raw_docs!")
        return

    total_chunks = 0

    for filename in txt_files:
        tool_name = filename.replace('.txt', '')
        filepath  = os.path.join(RAW_DOCS_DIR, filename)

        print(f"Processing {filename}...")

        with open(filepath, 'r', encoding='utf-8') as f:
            text = f.read()

        chunks = chunk_text(text)
        print(f"  Created {len(chunks)} chunks")

        for i, chunk in enumerate(chunks):
            doc_id    = f"{tool_name}_chunk_{i}"
            embedding = model.encode(chunk).tolist()

            collection.upsert(
                ids        =[doc_id],
                embeddings =[embedding],
                documents  =[chunk],
                metadatas  =[{"tool": tool_name, "chunk_index": i}]
            )

        total_chunks += len(chunks)
        print(f"  Ingested {filename} successfully")

    print(f"\nDone! Total chunks ingested: {total_chunks}")
    print(f"Tools in KB: {', '.join([f.replace('.txt','') for f in txt_files])}")

if __name__ == "__main__":
    ingest()





    