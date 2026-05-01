"""Pytest configuration for intent recognition tests."""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Setup test environment."""
    import os
    os.environ["ENVIRONMENT"] = "testing"
    os.environ["LOG_LEVEL"] = "ERROR"
    yield


@pytest.fixture
def sample_intents():
    """Sample intent data for testing."""
    return {
        "error_recovery": [
            "fix the error",
            "recover from crash",
            "handle exception",
            "retry failed operation",
            "system crashed"
        ],
        "vulnerability_scan": [
            "scan for vulnerabilities",
            "check security issues",
            "analyze threats",
            "find exploits",
            "security audit"
        ],
        "planning": [
            "create a plan",
            "make schedule",
            "organize work",
            "prepare roadmap",
            "generate workflow"
        ],
        "analysis": [
            "analyze data",
            "examine results",
            "review output",
            "inspect model",
            "check performance"
        ],
        "query": [
            "what is status",
            "how does it work",
            "why failed",
            "find error",
            "show logs"
        ],
        "execute": [
            "execute workflow",
            "run pipeline",
            "start process",
            "trigger job",
            "launch task"
        ]
    }