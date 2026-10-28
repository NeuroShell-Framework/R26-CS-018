"""
AEERE Step 2 — Error Classifier module
Drop this file next to error_classifier.joblib in your engine folder.
Usage:
    from aeere_classifier import classify_error, suggest_strategy
    etype = classify_error(error_message, command)   # -> "command_not_found"
    strat = suggest_strategy(etype)                   # -> "INSTALL_TOOL"
"""
import os, joblib

# load the trained model (same folder as this file)
_MODEL_PATH = os.path.join(os.path.dirname(__file__), "error_classifier.joblib")
_clf = joblib.load(_MODEL_PATH)

# maps each predicted error type -> which fix strategy the engine should apply
_STRATEGY_MAP = {
    "command_not_found":   "INSTALL_TOOL",        # tool missing -> apt-get install
    "package_not_found":   "INSTALL_TOOL",        # wrong/old pkg -> apt update + install
    "dependency_error":    "INSTALL_TOOL",        # missing dependency -> install it
    "permission_error":    "FIX_AUTH",            # add sudo / elevate
    "authentication_error":"FIX_AUTH",            # fix credentials / keys
    "port_conflict":       "ADJUST_TIMEOUT",      # change port / free it
    "network_error":       "ADJUST_TIMEOUT",      # retry / check DNS
    "syntax_error":        "FIX_SYNTAX",          # rewrite flags via RAG
    "file_not_found":      "FIX_SYNTAX",          # correct the path
    "service_error":       "ESCALATE",            # restart service / escalate
}

def classify_error(error_message: str, command: str = "") -> str:
    """Return the predicted error type for a Kali error message."""
    text = f"{error_message} [CMD] {command}"
    return _clf.predict([text])[0]

def suggest_strategy(error_type: str) -> str:
    """Return the fix strategy for a given error type."""
    return _STRATEGY_MAP.get(error_type, "ESCALATE")

# quick self-test
if __name__ == "__main__":
    samples = [
        ("bash: nmpa: command not found", "nmpa -sV 10.0.0.5"),
        ("Permission denied", "systemctl start ssh"),
        ("Address already in use", "python3 -m http.server 80"),
        ("Could not resolve host", "git clone https://github.com/x/y"),
    ]
    for em, cmd in samples:
        et = classify_error(em, cmd)
        print(f"{em:40s} -> {et:20s} -> {suggest_strategy(et)}")
