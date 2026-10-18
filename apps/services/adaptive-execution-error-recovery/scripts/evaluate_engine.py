import argparse, os, sys
from collections import Counter

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from kali_data.dataset_loader import load_dataset
from src.classification.regex_classifier import RegexClassifier


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="kali_data/kali_linux_error.csv")
    ap.add_argument("--no-embedding", action="store_true")
    args = ap.parse_args()

    print("=" * 64)
    print(" NeuroShell C3 (AEERE) - Error Classifier Accuracy")
    print("=" * 64)

    scenarios = load_dataset(args.data)
    print(" Scenarios   :", len(scenarios))

    regex_clf = RegexClassifier()
    try:
        regex_clf.enrich_from_dataset(scenarios)
    except Exception as e:
        print(" (regex enrich skipped:", e, ")")

    embed_clf = None
    if not args.no_embedding:
        try:
            from src.classification.embedding_classifier import EmbeddingClassifier
            print(" Loading embedding model...")
            embed_clf = EmbeddingClassifier()
        except Exception as e:
            print(" (embedding disabled:", e, ")")

    print(" Model       :", "regex + embedding" if embed_clf else "regex only", "\n")

    y_true, y_pred = [], []
    by_method = Counter()
    for s in scenarios:
        stderr = s.get("error_message", "") or ""
        gt = s.get("error_class", "UNKNOWN")
        cls, conf = regex_clf.classify(stderr, 1)
        used = "regex"
        if cls is None and embed_clf is not None:
            cls, conf = embed_clf.classify(stderr)
            used = "embedding"
        if cls is None:
            cls, used = "UNKNOWN", "none"
        y_true.append(gt)
        y_pred.append(cls)
        by_method[used] += 1

    correct = sum(1 for a, b in zip(y_true, y_pred) if a == b)
    acc = correct / len(y_true) if y_true else 0.0

    print("-" * 64)
    print("  OVERALL ACCURACY : {:.2f} %    ({}/{})".format(acc * 100, correct, len(y_true)))
    print("-" * 64)
    print("  classified by    :", dict(by_method), "\n")

    try:
        from sklearn.metrics import classification_report, confusion_matrix
        labels = sorted(set(y_true) | set(y_pred))
        print("Per-class report:")
        print(classification_report(y_true, y_pred, labels=labels, digits=3, zero_division=0))
        print("Confusion matrix (rows=true, cols=pred):")
        cm = confusion_matrix(y_true, y_pred, labels=labels)
        short = [l[:12] for l in labels]
        print(" " * 14 + " ".join("{:>12}".format(x) for x in short))
        for i, row in enumerate(cm):
            print("{:>12}  ".format(short[i]) + " ".join("{:>12}".format(v) for v in row))
    except Exception as e:
        print("(report skipped:", e, ")")


if __name__ == "__main__":
    main()