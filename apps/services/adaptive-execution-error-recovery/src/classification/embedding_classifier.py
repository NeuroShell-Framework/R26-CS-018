"""
AEERE Step 2 — EmbeddingClassifier (ML-backed, trained on the 8,000-row dataset).
Drop-in replacement for the sentence-transformers version.
Same interface:  classify(stderr) -> (error_class, confidence) or (None, 0.0)
Faster, fully offline (no model download), trained on project data.
Place error_classifier.joblib in the SAME folder as this file.
"""
import os
import joblib

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "error_classifier.joblib")

# dataset labels (what the model predicts)  ->  engine taxonomy labels
_LABEL_MAP = {
    "command_not_found":    "TOOL_NOT_INSTALLED",
    "package_not_found":    "TOOL_NOT_INSTALLED",
    "dependency_error":     "TOOL_NOT_INSTALLED",
    "permission_error":     "PERMISSION_DENIED",
    "authentication_error": "AUTH_FAILURE",
    "network_error":        "NETWORK_UNREACHABLE",
    "syntax_error":         "WRONG_SYNTAX",
    "file_not_found":       "WRONG_SYNTAX",
    "port_conflict":        "RESOURCE_EXHAUSTION",
    "service_error":        None,   # no clean taxonomy match -> let LLM (Step 3) decide
}

_CONF_THRESHOLD = 0.70   # same threshold as the original embedding classifier


class EmbeddingClassifier:
    """ML classifier that mimics the original embedding-based interface."""

    def __init__(self):
        self.model = joblib.load(_MODEL_PATH)

    def classify(self, stderr: str) -> tuple:
        text = (stderr or "")[:512]
        if not text.strip():
            return None, 0.0
        proba = self.model.predict_proba([text])[0]
        idx = proba.argmax()
        raw_label = self.model.classes_[idx]
        confidence = float(proba[idx])
        mapped = _LABEL_MAP.get(raw_label)
        # unknown mapping or low confidence -> defer to next layer
        if mapped is None or confidence < _CONF_THRESHOLD:
            return None, 0.0
        return mapped, confidence


# quick self-test
if __name__ == "__main__":
    clf = EmbeddingClassifier()
    tests = [
        "bash: gobuster: command not found",
        "Permission denied",
        "No route to host",
        "Invalid option: --invalid-flag",
        "Authentication failed",
        "Address already in use",
    ]
    for t in tests:
        print(f"{t:40s} -> {clf.classify(t)}")
