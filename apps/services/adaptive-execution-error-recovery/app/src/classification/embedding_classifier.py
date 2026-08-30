import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

EXEMPLARS = {
    'TOOL_NOT_INSTALLED': [
        'bash: gobuster: command not found',
        'nmap: command not found',
        'No such file or directory: ffuf',
    ],
    'PERMISSION_DENIED': [
        'Permission denied: you must be root',
        'Operation not permitted',
        'EACCES: access denied',
    ],
    'NETWORK_UNREACHABLE': [
        'No route to host',
        'Connection refused by remote host',
        'EHOSTUNREACH network is unreachable',
    ],
    'WRONG_SYNTAX': [
        'Invalid option: --invalid-flag',
        'unrecognized argument: -xyz',
        'usage: nmap [Scan Type(s)] [Options]',
    ],
    'RESOURCE_EXHAUSTION': [
        'Cannot allocate memory',
        'Too many open files',
        'Out of memory: Kill process',
    ],
    'TIMEOUT': [
        'Read timeout exceeded',
        'ETIMEDOUT connection timed out',
        'Operation timed out after 30 seconds',
    ],
    'AUTH_FAILURE': [
        'Permission denied (publickey)',
        'Authentication failed',
        'Invalid credentials supplied',
    ],
    'VERSION_MISMATCH': [
        'Unrecognized option in this version',
        'deprecated flag removed in version 3',
        'requires gobuster version 3.6 or higher',
    ],
}


class EmbeddingClassifier:

    def __init__(self):
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.centroids = self._compute_centroids()

    def _compute_centroids(self) -> dict:
        centroids = {}
        for cls, examples in EXEMPLARS.items():
            embeddings = self.model.encode(examples)
            centroids[cls] = np.mean(embeddings, axis=0)
        return centroids

    def classify(self, stderr: str) -> tuple:
        query = self.model.encode([stderr[:512]])[0]
        scores = {}
        for cls, centroid in self.centroids.items():
            score = cosine_similarity([query], [centroid])[0][0]
            scores[cls] = float(score)
        best = max(scores, key=scores.get)
        if scores[best] >= 0.70:
            return best, scores[best]
        return None, 0.0
