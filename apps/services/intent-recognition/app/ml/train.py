"""Training script for intent classification model."""

import argparse
import json
import sys
from pathlib import Path

from app.ml.classifier import IntentClassifier


def main():
    parser = argparse.ArgumentParser(description="Train intent classification model")
    parser.add_argument("--data", type=str, help="Path to training data JSON file")
    parser.add_argument("--output", type=str, default="models/intent_model.joblib", help="Output model path")
    parser.add_argument("--test-size", type=float, default=0.2, help="Test set ratio")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()

    training_data = None
    if args.data:
        data_path = Path(args.data)
        if data_path.exists():
            with open(data_path, "r") as f:
                raw_data = json.load(f)
                training_data = [(item["text"], item["intent"]) for item in raw_data]
            print(f"Loaded {len(training_data)} training samples from {args.data}")
        else:
            print(f"Warning: Training data file not found: {args.data}")

    print("Training intent classifier...")
    classifier = IntentClassifier()
    results = classifier.train(training_data=training_data, test_size=args.test_size)

    print(f"\n{'='*50}")
    print("TRAINING RESULTS")
    print(f"{'='*50}")
    print(f"Training samples: {results['training_samples']}")
    print(f"Test samples: {results['test_samples']}")
    print(f"Accuracy: {results['accuracy']:.2%}")

    if args.verbose:
        print(f"\nClassification Report:")
        for label, metrics in results["report"].items():
            if label not in ["accuracy", "macro avg", "weighted avg"]:
                print(f"  {label}: precision={metrics['precision']:.2f}, recall={metrics['recall']:.2f}, f1={metrics['f1-score']:.2f}")

    output_path = classifier.save(args.output)
    print(f"\nModel saved to: {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())