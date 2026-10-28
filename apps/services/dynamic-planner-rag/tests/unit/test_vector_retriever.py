import pytest
from src.rag.vector_retriever import VectorRetriever

def test_vector_retriever_initialization():
    retriever = VectorRetriever()
    assert retriever.collection is not None
    assert retriever.collection.name == "tool_documentation"

def test_vector_retriever_retrieve_with_tool_hint():
    retriever = VectorRetriever()
    docs = retriever.retrieve("stealth scan open ports", tool_hint="nmap", top_k=2)
    assert isinstance(docs, list)
    for d in docs:
        assert d["tool"] == "nmap"
        assert "score" in d

def test_vector_retriever_score_threshold_filtering():
    retriever = VectorRetriever()
    # High threshold should filter out low score chunks
    docs_filtered = retriever.retrieve("random text query", score_threshold=0.99)
    assert len(docs_filtered) == 0 or all(d["score"] >= 0.99 for d in docs_filtered)
