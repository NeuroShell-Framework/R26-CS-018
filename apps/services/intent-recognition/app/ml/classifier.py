"""Machine learning components for intent classification."""

import os
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split


class IntentClassifier:
    """ML-based intent classifier using TF-IDF and Logistic Regression."""

    DEFAULT_TRAINING_DATA = [
        ("fix the error that occurred", "recover_error"),
        ("recover from the crash", "recover_error"),
        ("handle this exception", "recover_error"),
        ("retry the failed operation", "recover_error"),
        ("the system crashed", "recover_error"),
        ("recover from failure", "recover_error"),
        ("fix broken pipeline", "recover_error"),
        ("resume after error", "recover_error"),
        ("handle timeout error", "recover_error"),
        ("recover from timeout", "recover_error"),
        
        ("scan for vulnerabilities", "scan_vulnerability"),
        ("check for security issues", "scan_vulnerability"),
        ("analyze security threats", "scan_vulnerability"),
        ("find vulnerabilities in the model", "scan_vulnerability"),
        ("check for exploits", "scan_vulnerability"),
        ("security audit", "scan_vulnerability"),
        ("scan for threats", "scan_vulnerability"),
        ("vulnerability assessment", "scan_vulnerability"),
        ("check for risks", "scan_vulnerability"),
        ("analyze security risks", "scan_vulnerability"),
        
        ("create a plan for the task", "create_plan"),
        ("make a plan", "create_plan"),
        ("schedule the project", "create_plan"),
        ("organize the work", "create_plan"),
        ("plan the execution", "create_plan"),
        ("generate a plan", "create_plan"),
        ("prepare a roadmap", "create_plan"),
        ("arrange the steps", "create_plan"),
        ("create workflow", "create_plan"),
        ("develop a plan", "create_plan"),
        
        ("analyze this data", "analyze"),
        ("examine the results", "analyze"),
        ("review the output", "analyze"),
        ("inspect the model", "analyze"),
        ("check the performance", "analyze"),
        ("evaluate the system", "analyze"),
        ("assess the results", "analyze"),
        ("review the metrics", "analyze"),
        ("inspect the code", "analyze"),
        ("examine the logs", "analyze"),
        
        ("what is the status", "query"),
        ("how does this work", "query"),
        ("why did it fail", "query"),
        ("when will it complete", "query"),
        ("where is the file", "query"),
        ("who can access it", "query"),
        ("find the error", "query"),
        ("search for results", "query"),
        ("show me the logs", "query"),
        ("get the details", "query"),
        
        ("execute the workflow", "execute"),
        ("run the pipeline", "execute"),
        ("start the process", "execute"),
        ("trigger the job", "execute"),
        ("launch the task", "execute"),
        ("begin execution", "execute"),
        ("run this command", "execute"),
        ("start processing", "execute"),
        ("initiate workflow", "execute"),
        ("execute now", "execute"),
    ]

    INTENT_TYPE_MAPPING = {
        "recover_error": ("RECOVER_ERROR", "error_recovery"),
        "scan_vulnerability": ("SCAN_VULNERABILITY", "vulnerability_scan"),
        "create_plan": ("CREATE_PLAN", "planning"),
        "analyze": ("ANALYZE", "analysis"),
        "query": ("QUERY", "query"),
        "execute": ("EXECUTE", "command"),
    }

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.classifier: Optional[LogisticRegression] = None
        self.is_trained = False

    def _preprocess_text(self, text: str) -> str:
        """Preprocess text for classification."""
        return text.lower().strip()

    def train(self, training_data: Optional[list[tuple[str, str]]] = None, test_size: float = 0.2) -> dict[str, Any]:
        """Train the intent classifier."""
        data = training_data or self.DEFAULT_TRAINING_DATA
        
        texts = [self._preprocess_text(text) for text, _ in data]
        labels = [label for _, label in data]

        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=test_size, random_state=42, stratify=labels
        )

        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=500,
            min_df=1,
            max_df=0.95,
        )

        X_train_tfidf = self.vectorizer.fit_transform(X_train)
        X_test_tfidf = self.vectorizer.transform(X_test)

        self.classifier = LogisticRegression(
            max_iter=1000,
            random_state=42,
            multi_class="multinomial",
            solver="lbfgs",
            class_weight="balanced",
        )

        self.classifier.fit(X_train_tfidf, y_train)

        y_pred = self.classifier.predict(X_test_tfidf)
        report = classification_report(y_test, y_pred, output_dict=True)

        self.is_trained = True

        return {
            "training_samples": len(X_train),
            "test_samples": len(X_test),
            "accuracy": report["accuracy"],
            "report": report,
        }

    def predict(self, text: str) -> tuple[str, str, float]:
        """Predict intent from text."""
        if not self.is_trained:
            self.train()

        processed_text = self._preprocess_text(text)
        text_tfidf = self.vectorizer.transform([processed_text])

        predicted_label = self.classifier.predict(text_tfidf)[0]
        probabilities = self.classifier.predict_proba(text_tfidf)[0]
        confidence = float(max(probabilities))

        intent_type, intent_category = self.INTENT_TYPE_MAPPING.get(
            predicted_label, ("QUERY", "unknown")
        )

        return intent_type, intent_category, confidence

    def predict_with_alternatives(self, text: str, top_n: int = 3) -> tuple[dict, list[dict]]:
        """Predict intent with alternative predictions."""
        if not self.is_trained:
            self.train()

        processed_text = self._preprocess_text(text)
        text_tfidf = self.vectorizer.transform([processed_text])

        predicted_label = self.classifier.predict(text_tfidf)[0]
        probabilities = self.classifier.predict_proba(text_tfidf)[0]

        feature_names = self.vectorizer.get_feature_names_out()
        top_indices = np.argsort(probabilities)[::-1][:top_n]

        intent_type, intent_category = self.INTENT_TYPE_MAPPING.get(
            predicted_label, ("QUERY", "unknown")
        )

        main_intent = {
            "intent_type": intent_type,
            "intent_category": intent_category,
            "confidence": float(max(probabilities)),
        }

        alternatives = []
        for idx in top_indices[1:]:
            label = self.classifier.classes_[idx]
            if label != predicted_label:
                alt_type, alt_cat = self.INTENT_TYPE_MAPPING.get(label, ("QUERY", "unknown"))
                alternatives.append({
                    "intent_type": alt_type,
                    "intent_category": alt_cat,
                    "confidence": float(probabilities[idx]),
                    "reason": f"Alternative prediction (probability: {probabilities[idx]:.2%})",
                })

        return main_intent, alternatives

    def save(self, path: Optional[str] = None) -> str:
        """Save the trained model."""
        save_path = path or self.model_path or "intent_model.joblib"
        
        model_data = {
            "vectorizer": self.vectorizer,
            "classifier": self.classifier,
            "is_trained": self.is_trained,
        }
        
        joblib.dump(model_data, save_path)
        return save_path

    def load(self, path: str) -> None:
        """Load a trained model."""
        model_data = joblib.load(path)
        self.vectorizer = model_data["vectorizer"]
        self.classifier = model_data["classifier"]
        self.is_trained = model_data["is_trained"]

    def get_supported_intents(self) -> list[dict]:
        """Get list of supported intents."""
        return [
            {"type": "RECOVER_ERROR", "category": "error_recovery", "description": "Recover from errors, failures, or crashes"},
            {"type": "SCAN_VULNERABILITY", "category": "vulnerability_scan", "description": "Scan for security vulnerabilities or threats"},
            {"type": "CREATE_PLAN", "category": "planning", "description": "Create plans, schedules, or workflows"},
            {"type": "ANALYZE", "category": "analysis", "description": "Analyze data, results, or system state"},
            {"type": "QUERY", "category": "query", "description": "Ask questions or search for information"},
            {"type": "EXECUTE", "category": "command", "description": "Execute commands, pipelines, or workflows"},
        ]


_classifier_instance: Optional[IntentClassifier] = None


def get_classifier() -> IntentClassifier:
    """Get or create the global classifier instance."""
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = IntentClassifier()
    return _classifier_instance