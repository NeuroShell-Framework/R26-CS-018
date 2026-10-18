# Integration helper for AEERE Step 2 (error classification)
import joblib
_clf = joblib.load("error_classifier.joblib")

def classify_error(error_message: str, command: str = "") -> str:
    """Return the predicted error_type for a Kali error message."""
    text = f"{error_message} [CMD] {command}"
    return _clf.predict([text])[0]

if __name__ == "__main__":
    # quick demo
    tests = [
        ("bash: nmpa: command not found", "nmpa -sV 10.0.0.5"),
        ("Permission denied", "cat /etc/shadow"),
        ("Address already in use", "python3 -m http.server 80"),
        ("Could not resolve host", "git clone https://github.com/x/y"),
    ]
    for em, cmd in tests:
        print(f"{classify_error(em, cmd):20s} <- {em!r}")
