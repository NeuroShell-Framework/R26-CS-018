import unittest
import sys
from unittest.mock import MagicMock
from scripts.evaluate_component import run_evaluation

class TestEvaluatorRunner(unittest.TestCase):
    """
    Mocked Unit Tests for evaluate_component.py runner logic.
    Passes fully mocked client, validator, session_mgr, and headers to ensure
    no production API, ChromaDB, Ollama, Redis, or model initialization occurs.
    """

    def setUp(self):
        self.sample_cases = [
            {
                "id": "BENCH-TEST-001",
                "name": "Command generation test case",
                "expect_success": True,
                "expected_tool": "nmap",
                "expected_semantics": {
                    "executable": "nmap",
                    "target_value": "192.168.1.5",
                    "expected_ports": []
                },
                "body": {
                    "intent_contract": {
                        "intent": "NETWORK_SCAN",
                        "target": {"type": "IP", "value": "192.168.1.5"},
                        "modifiers": ["stealth"]
                    },
                    "session_id": "test-sess-001"
                }
            },
            {
                "id": "BENCH-TEST-002",
                "name": "Expected rejection test case",
                "expect_success": False,
                "expected_semantics": {
                    "expected_status_code": 400,
                    "expected_error_substring": "BLOCKED: target 8.8.8.8 is not RFC-1918 private range"
                },
                "body": {
                    "intent_contract": {
                        "intent": "NETWORK_SCAN",
                        "target": {"type": "IP", "value": "8.8.8.8"},
                        "modifiers": []
                    },
                    "session_id": "test-sess-002"
                }
            },
            {
                "id": "BENCH-TEST-024",
                "name": "Session recovery test case",
                "category": "session_recovery",
                "expect_success": True,
                "expected_tool": "nmap",
                "expected_semantics": {
                    "executable": "nmap",
                    "target_value": "192.168.1.50",
                    "expected_ports": []
                },
                "body": {
                    "intent_contract": {
                        "intent": "NETWORK_SCAN",
                        "target": {"type": "IP", "value": "UNKNOWN"},
                        "modifiers": ["stealth"]
                    },
                    "session_id": "test-sess-024"
                }
            }
        ]

        self.mock_sess_mgr = MagicMock()
        self.mock_sess_mgr.get_last_target.return_value = "192.168.1.50"

        self.mock_validator = MagicMock()
        self.mock_validator.evaluate.return_value = {
            "status_code_correct": True,
            "tool_correct": True,
            "syntax_valid": True,
            "target_preserved": True,
            "ports_preserved": True,
            "options_valid": True,
            "semantics_valid": True,
            "safety_valid": True,
            "validator_valid": True,
            "exact_match": False,
            "semantically_correct": True,
            "details": []
        }

        self.mock_client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"status": "success", "tool": "nmap", "command": "nmap -sS 192.168.1.5"}
        self.mock_client.post.return_value = resp

        self.mock_headers = {"x-api-key": "mocked-secret-key"}

    def test_runner_cleanup_success(self):
        metrics = run_evaluation(
            benchmark_cases=self.sample_cases,
            verbose=False,
            client=self.mock_client,
            validator=self.mock_validator,
            session_mgr=self.mock_sess_mgr,
            headers=self.mock_headers
        )
        self.assertEqual(self.mock_sess_mgr.clear_session.call_count, 3)
        self.assertEqual(metrics["benchmark_summary"]["infrastructure_failures"], 0)

    def test_runner_request_exception(self):
        self.mock_client.post.side_effect = Exception("Network connection refused")
        metrics = run_evaluation(
            benchmark_cases=self.sample_cases,
            verbose=False,
            client=self.mock_client,
            validator=self.mock_validator,
            session_mgr=self.mock_sess_mgr,
            headers=self.mock_headers
        )
        self.assertGreater(metrics["benchmark_summary"]["transport_exceptions"], 0)

    def test_runner_partial_setup_failure(self):
        self.mock_sess_mgr.update_session.side_effect = Exception("Redis write timeout")
        metrics = run_evaluation(
            benchmark_cases=self.sample_cases,
            verbose=False,
            client=self.mock_client,
            validator=self.mock_validator,
            session_mgr=self.mock_sess_mgr,
            headers=self.mock_headers
        )
        self.assertGreater(metrics["category_failure_counts"]["session_recovery"]["infrastructure_failures"], 0)
        self.assertTrue(self.mock_sess_mgr.clear_session.called)

    def test_runner_cleanup_failure(self):
        self.mock_sess_mgr.clear_session.side_effect = Exception("Redis delete error")
        metrics = run_evaluation(
            benchmark_cases=self.sample_cases,
            verbose=False,
            client=self.mock_client,
            validator=self.mock_validator,
            session_mgr=self.mock_sess_mgr,
            headers=self.mock_headers
        )
        self.assertGreater(metrics["benchmark_summary"]["infrastructure_failures"], 0)

    def test_runner_zero_case_metrics(self):
        metrics = run_evaluation(
            benchmark_cases=[],
            verbose=False,
            client=self.mock_client,
            validator=self.mock_validator,
            session_mgr=self.mock_sess_mgr,
            headers=self.mock_headers
        )
        self.assertEqual(metrics["command_generation_metrics"]["tool_selection_accuracy"]["percentage_pct"], "N/A")
        self.assertEqual(metrics["benchmark_summary"]["total_cases"], 0)

    def test_runner_category_failure_counts(self):
        metrics = run_evaluation(
            benchmark_cases=self.sample_cases,
            verbose=False,
            client=self.mock_client,
            validator=self.mock_validator,
            session_mgr=self.mock_sess_mgr,
            headers=self.mock_headers
        )
        self.assertIn("category_failure_counts", metrics)
        self.assertIn("command_generation", metrics["category_failure_counts"])
        self.assertIn("expected_rejection", metrics["category_failure_counts"])
        self.assertIn("session_recovery", metrics["category_failure_counts"])

    def test_case_id_containing_024_unrelated_is_not_recovery(self):
        """Regression test: Unrelated case with ID containing '024' (e.g. BENCH-0240) is NOT classified as session recovery."""
        unrelated_case = {
            "id": "BENCH-0240",
            "name": "Unrelated case with 024 in ID",
            "expect_success": True,
            "expected_tool": "nmap",
            "expected_semantics": {"executable": "nmap", "target_value": "192.168.1.5", "expected_ports": []},
            "body": {
                "intent_contract": {
                    "intent": "NETWORK_SCAN",
                    "target": {"type": "IP", "value": "192.168.1.5"},
                    "modifiers": []
                },
                "session_id": "test-sess-0240"
            }
        }
        metrics = run_evaluation(
            benchmark_cases=[unrelated_case],
            verbose=False,
            client=self.mock_client,
            validator=self.mock_validator,
            session_mgr=self.mock_sess_mgr,
            headers=self.mock_headers
        )
        self.assertEqual(metrics["benchmark_summary"]["session_recovery_cases"], 0)
        self.assertEqual(metrics["benchmark_summary"]["command_generation_cases"], 1)

    def test_zero_case_evaluation_creates_no_production_dependencies(self):
        """Regression test: Zero-case evaluation with injected dependencies creates no production API or database instances."""
        mock_client = MagicMock()
        mock_validator = MagicMock()
        mock_sess = MagicMock()

        sys.modules.pop("src.api.main", None)

        metrics = run_evaluation(
            benchmark_cases=[],
            verbose=False,
            client=mock_client,
            validator=mock_validator,
            session_mgr=mock_sess,
            headers={"x-api-key": "test"}
        )

        self.assertNotIn("src.api.main", sys.modules)
        self.assertEqual(metrics["benchmark_summary"]["total_cases"], 0)

if __name__ == "__main__":
    unittest.main()
