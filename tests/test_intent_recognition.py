"""Tests for the intent recognition service."""

import pytest
from fastapi.testclient import TestClient

from app import app


client = TestClient(app)


class TestIntentRecognition:
    """Test suite for intent recognition service."""

    def test_health_endpoint(self):
        """Test health endpoint returns correct status."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "uptime" in data

    def test_recognize_error_intent(self):
        """Test recognition of error recovery intent."""
        response = client.post(
            "/api/v1/recognize",
            json={
                "text": "fix the error that occurred in the system",
                "return_alternatives": True,
                "use_ml": True
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "data" in data
        intent_data = data["data"]["intent"]
        assert intent_data["intent_type"] in ["recover_error", "RECOVER_ERROR"]
        assert intent_data["confidence"] > 0.0

    def test_recognize_vulnerability_intent(self):
        """Test recognition of vulnerability scan intent."""
        response = client.post(
            "/api/v1/recognize",
            json={
                "text": "scan for vulnerabilities in the model",
                "use_ml": True
            }
        )
        assert response.status_code == 200
        data = response.json()
        intent_data = data["data"]["intent"]
        assert intent_data["intent_type"] in ["scan_vulnerability", "SCAN_VULNERABILITY"]

    def test_recognize_planning_intent(self):
        """Test recognition of planning intent."""
        response = client.post(
            "/api/v1/recognize",
            json={
                "text": "create a plan for the project execution",
                "use_ml": True
            }
        )
        assert response.status_code == 200
        data = response.json()
        intent_data = data["data"]["intent"]
        assert intent_data["intent_type"] in ["create_plan", "CREATE_PLAN"]

    def test_recognize_analysis_intent(self):
        """Test recognition of analysis intent."""
        response = client.post(
            "/api/v1/recognize",
            json={
                "text": "analyze the performance metrics",
                "use_ml": True
            }
        )
        assert response.status_code == 200
        data = response.json()
        intent_data = data["data"]["intent"]
        assert intent_data["intent_type"] in ["analyze", "ANALYZE"]

    def test_recognize_query_intent(self):
        """Test recognition of query intent."""
        response = client.post(
            "/api/v1/recognize",
            json={
                "text": "what is the current status of the system",
                "use_ml": True
            }
        )
        assert response.status_code == 200
        data = response.json()
        intent_data = data["data"]["intent"]
        assert intent_data["intent_type"] in ["query", "QUERY"]

    def test_recognize_execute_intent(self):
        """Test recognition of execute intent."""
        response = client.post(
            "/api/v1/recognize",
            json={
                "text": "execute the pipeline now",
                "use_ml": True
            }
        )
        assert response.status_code == 200
        data = response.json()
        intent_data = data["data"]["intent"]
        assert intent_data["intent_type"] in ["execute", "EXECUTE"]

    def test_batch_recognize(self):
        """Test batch intent recognition."""
        response = client.post(
            "/api/v1/batch-recognize",
            json={
                "texts": [
                    "fix the error",
                    "scan for vulnerabilities",
                    "create a plan"
                ],
                "use_ml": True
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["processed_count"] == 3

    def test_keyword_based_fallback(self):
        """Test keyword-based classification fallback."""
        response = client.post(
            "/api/v1/recognize",
            json={
                "text": "fix the error",
                "use_ml": False
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["intent"]["intent_type"] in ["recover_error", "RECOVER_ERROR"]

    def test_model_info_endpoint(self):
        """Test model info endpoint."""
        response = client.get("/api/v1/model/info")
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert "is_trained" in data["data"]
        assert "supported_intents" in data["data"]

    def test_list_intents_endpoint(self):
        """Test list intents endpoint."""
        response = client.get("/api/v1/intents")
        assert response.status_code == 200
        data = response.json()
        intents = data["data"]
        assert len(intents) > 0

    def test_statistics_endpoint(self):
        """Test statistics endpoint."""
        response = client.get("/api/v1/statistics")
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert "total_predictions" in data["data"]

    def test_reset_statistics(self):
        """Test statistics reset."""
        response = client.post("/api/v1/reset-statistics")
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["message"] == "Statistics reset successfully"

    def test_training_endpoint(self):
        """Test model training endpoint."""
        training_data = {
            "data": [
                {"text": "fix error", "intent": "recover_error"},
                {"text": "scan security", "intent": "scan_vulnerability"},
                {"text": "make plan", "intent": "create_plan"},
                {"text": "analyze data", "intent": "analyze"},
                {"text": "what is this", "intent": "query"},
                {"text": "run pipeline", "intent": "execute"},
            ],
            "test_size": 0.3
        }
        response = client.post("/api/v1/train", json=training_data)
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["success"] is True

    def test_invalid_text(self):
        """Test with invalid/empty text."""
        response = client.post(
            "/api/v1/recognize",
            json={"text": ""}
        )
        assert response.status_code == 422

    def test_long_text(self):
        """Test with very long text."""
        long_text = " ".join(["analyze"] * 100)
        response = client.post(
            "/api/v1/recognize",
            json={"text": long_text}
        )
        assert response.status_code == 200

    def test_mixed_intent_text(self):
        """Test with text containing multiple intent signals."""
        response = client.post(
            "/api/v1/recognize",
            json={
                "text": "run the analysis and fix any errors found",
                "return_alternatives": True
            }
        )
        assert response.status_code == 200


class TestIntentClassifier:
    """Test suite for ML classifier."""

    def test_classifier_initialization(self):
        """Test classifier can be initialized."""
        from app.ml.classifier import IntentClassifier
        classifier = IntentClassifier()
        assert classifier is not None
        assert not classifier.is_trained

    def test_classifier_training(self):
        """Test classifier can be trained."""
        from app.ml.classifier import IntentClassifier
        classifier = IntentClassifier()
        result = classifier.train()
        assert classifier.is_trained
        assert "accuracy" in result

    def test_classifier_prediction(self):
        """Test classifier can predict."""
        from app.ml.classifier import IntentClassifier
        classifier = IntentClassifier()
        classifier.train()
        intent_type, category, confidence = classifier.predict("fix the error")
        assert intent_type in ["RECOVER_ERROR", "SCAN_VULNERABILITY", "CREATE_PLAN", "ANALYZE", "QUERY", "EXECUTE"]
        assert 0.0 <= confidence <= 1.0

    def test_classifier_alternatives(self):
        """Test classifier returns alternatives."""
        from app.ml.classifier import IntentClassifier
        classifier = IntentClassifier()
        classifier.train()
        main, alternatives = classifier.predict_with_alternatives("fix error", top_n=3)
        assert "intent_type" in main
        assert len(alternatives) >= 0

    def test_supported_intents(self):
        """Test getting supported intents."""
        from app.ml.classifier import IntentClassifier
        classifier = IntentClassifier()
        intents = classifier.get_supported_intents()
        assert len(intents) == 6
        assert all("type" in i and "category" in i for i in intents)


class TestEdgeCases:
    """Test edge cases."""

    def test_special_characters(self):
        """Test text with special characters."""
        response = client.post(
            "/api/v1/recognize",
            json={"text": "fix error @system #urgent!"}
        )
        assert response.status_code == 200

    def test_numbers_in_text(self):
        """Test text with numbers."""
        response = client.post(
            "/api/v1/recognize",
            json={"text": "analyze results from test 123"}
        )
        assert response.status_code == 200

    def test_unicode_text(self):
        """Test text with unicode."""
        response = client.post(
            "/api/v1/recognize",
            json={"text": "fix error in système"}
        )
        assert response.status_code == 200

    def test_very_short_text(self):
        """Test very short text."""
        response = client.post(
            "/api/v1/recognize",
            json={"text": "run"}
        )
        assert response.status_code == 200

    def test_gibberish_text(self):
        """Test gibberish text."""
        response = client.post(
            "/api/v1/recognize",
            json={"text": "xyzabc123 random words"}
        )
        assert response.status_code == 200