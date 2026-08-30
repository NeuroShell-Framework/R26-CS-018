import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import chromadb
from sentence_transformers import SentenceTransformer
from dotenv import load_dotenv

load_dotenv()

CHROMA_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'knowledge_base', 'chroma_db')


DEFAULT_SCORE_THRESHOLD = float(os.getenv("RAG_SCORE_THRESHOLD", "0.30"))


class VectorRetriever:
    def __init__(self):
        self.client = chromadb.PersistentClient(path=CHROMA_DIR)
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.collection = self.client.get_or_create_collection(
            name="tool_documentation",
            metadata={"hnsw:space": "cosine"}
        )
        print("VectorRetriever initialized")

    def retrieve(self, query: str, tool_hint: str = None, top_k: int = 3, score_threshold: float = DEFAULT_SCORE_THRESHOLD):
        embedding = self.model.encode(query).tolist()

        where = {"tool": tool_hint} if tool_hint else None

        results = self.collection.query(
            query_embeddings=[embedding],
            n_results=top_k,
            where=where
        )

        docs = []

        if results and results.get('documents') and results['documents'][0]:
            for i, doc in enumerate(results['documents'][0]):
                score = round(1.0 - results["distances"][0][i], 4)
                if score >= score_threshold:
                    docs.append({
                        "content": doc,
                        "tool": results["metadatas"][0][i]["tool"],
                        "score": score
                    })

        return docs


    def add_document(self, content: str, metadata: dict) -> int:
        import uuid
        tool_name = metadata.get("tool", "custom")
        words = content.split()
        chunk_size = 80
        overlap = 20
        chunks = []
        i = 0
        while i < len(words):
            chunk = ' '.join(words[i:i + chunk_size])
            chunks.append(chunk)
            i += chunk_size - overlap
        if not chunks and content:
            chunks = [content]

        base_id = metadata.get("id") or f"{tool_name}_{uuid.uuid4().hex[:8]}"
        ids = []
        embeddings = []
        documents = []
        metadatas = []

        for idx, chunk in enumerate(chunks):
            doc_id = f"{base_id}_chunk_{idx}" if len(chunks) > 1 else base_id
            emb = self.model.encode(chunk)
            embedding = emb.tolist() if hasattr(emb, "tolist") else list(emb)
            chunk_meta = {**metadata, "tool": tool_name, "chunk_index": idx}
            ids.append(doc_id)
            embeddings.append(embedding)
            documents.append(chunk)
            metadatas.append(chunk_meta)

        self.collection.upsert(
            ids=ids,
            embeddings=embeddings,
            documents=documents,
            metadatas=metadatas
        )
        return len(chunks)


if __name__ == "__main__":
    retriever = VectorRetriever()
    results = retriever.retrieve("stealth scan open ports", tool_hint="nmap")

    for r in results:
        print(f"\nTool: {r['tool']} | Score: {r['score']:.3f}")
        print(r["content"][:200])