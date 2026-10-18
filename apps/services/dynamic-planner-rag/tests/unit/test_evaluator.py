import unittest
import uuid
from unittest.mock import patch, MagicMock
from scripts.cli_ast_validator import CLIASTValidator
from src.session.session_context_manager import SessionContextManager

class TestCLIASTEvaluator(unittest.TestCase):

    def setUp(self):
        self.validator = CLIASTValidator()

    def test_wrong_executable_fails(self):
        case = {
            "id": "TEST-001",
            "name": "Nmap requested but gobuster generated",
            "expected_tool": "nmap",
            "expect_success": True,
            "expected_semantics": {
                "executable": "nmap",
                "target_value": "192.168.1.50",
                "expected_ports": [],
                "canonical_reference_command": "nmap -sS 192.168.1.50"
            },
            "body": {
                "intent_contract": {
                    "intent": "NETWORK_SCAN",
                    "target": {"type": "IP", "value": "192.168.1.50"},
                    "modifiers": ["stealth"]
                }
            }
        }
        res = self.validator.evaluate("gobuster dir -u http://192.168.1.50 -w common.txt", case, {"status": "success", "tool": "gobuster"}, status_code=200)
        self.assertFalse(res["tool_correct"])
        self.assertFalse(res["semantically_correct"])

    def test_partial_ip_match_fails(self):
        case = {
            "id": "TEST-002",
            "name": "Target IP 192.168.1.5 must not match 192.168.1.50",
            "expected_tool": "nmap",
            "expect_success": True,
            "expected_semantics": {
                "executable": "nmap",
                "target_value": "192.168.1.5",
                "expected_ports": []
            },
            "body": {
                "intent_contract": {
                    "intent": "NETWORK_SCAN",
                    "target": {"type": "IP", "value": "192.168.1.5"},
                    "modifiers": []
                }
            }
        }
        res = self.validator.evaluate("nmap -sS 192.168.1.50", case, {"status": "success", "tool": "nmap"}, status_code=200)
        self.assertFalse(res["target_preserved"])
        self.assertFalse(res["semantically_correct"])

    def test_target_inside_wordlist_path_fails(self):
        """Target IP inside a wordlist path or unrelated option must NOT count as target preservation."""
        case = {
            "id": "TEST-002B",
            "name": "Target IP inside wordlist path argument",
            "expected_tool": "gobuster",
            "expect_success": True,
            "expected_semantics": {
                "executable": "gobuster",
                "target_value": "192.168.1.5",
                "expected_ports": [80]
            },
            "body": {
                "intent_contract": {
                    "intent": "DIRECTORY_BRUTEFORCE",
                    "target": {"type": "URL", "value": "192.168.1.5"},
                    "ports": [80],
                    "modifiers": []
                }
            }
        }
        # IP 192.168.1.5 appears ONLY in wordlist path (-w), target URL -u points to 192.168.1.99
        res = self.validator.evaluate("gobuster dir -u http://192.168.1.99 -w /usr/share/wordlists/192.168.1.5/common.txt", case, {"status": "success", "tool": "gobuster"}, status_code=200)
        self.assertFalse(res["target_preserved"])
        self.assertFalse(res["semantically_correct"])

    def test_subnet_match_requires_prefix(self):
        case = {
            "id": "TEST-003",
            "name": "Subnet target requires /24 CIDR prefix",
            "expected_tool": "nmap",
            "expect_success": True,
            "expected_semantics": {
                "executable": "nmap",
                "target_value": "192.168.0.0/24",
                "expected_ports": []
            },
            "body": {
                "intent_contract": {
                    "intent": "NETWORK_SCAN",
                    "target": {"type": "SUBNET", "value": "192.168.0.0/24"},
                    "modifiers": ["stealth"]
                }
            }
        }
        # Command with plain IP missing /24 CIDR prefix
        res_fail = self.validator.evaluate("nmap -sS -T2 192.168.0.0", case, {"status": "success", "tool": "nmap"}, status_code=200)
        self.assertFalse(res_fail["target_preserved"])

        # Command with proper CIDR prefix
        res_pass = self.validator.evaluate("nmap -sS -T2 192.168.0.0/24", case, {"status": "success", "tool": "nmap"}, status_code=200)
        self.assertTrue(res_pass["target_preserved"])

    def test_port_matching_prevents_thread_count_false_pass(self):
        case = {
            "id": "TEST-004",
            "name": "Thread count -t 50 must not satisfy missing port 50",
            "expected_tool": "gobuster",
            "expect_success": True,
            "expected_semantics": {
                "executable": "gobuster",
                "target_value": "192.168.1.50",
                "expected_ports": [50]
            },
            "body": {
                "intent_contract": {
                    "intent": "DIRECTORY_BRUTEFORCE",
                    "target": {"type": "URL", "value": "192.168.1.50"},
                    "ports": [50],
                    "modifiers": ["threads:50"]
                }
            }
        }
        # URL is http://192.168.1.50 (default port 80), -t 50 is thread count
        res = self.validator.evaluate("gobuster dir -u http://192.168.1.50 -w /usr/share/wordlists/common.txt -t 50", case, {"status": "success", "tool": "gobuster"}, status_code=200)
        self.assertFalse(res["ports_preserved"])
        self.assertFalse(res["semantically_correct"])

    def test_port_flag_aliases_and_ranges(self):
        """Supports -p 80,443, -p 1-1024, and -p- port flag forms."""
        case = {
            "id": "TEST-004B",
            "name": "Port range and aliases test",
            "expected_tool": "nmap",
            "expect_success": True,
            "expected_semantics": {
                "executable": "nmap",
                "target_value": "192.168.1.5",
                "expected_ports": [80]
            },
            "body": {
                "intent_contract": {
                    "intent": "NETWORK_SCAN",
                    "target": {"type": "IP", "value": "192.168.1.5"},
                    "ports": [80],
                    "modifiers": []
                }
            }
        }
        # Explicit port range 1-1024 includes 80
        res_range = self.validator.evaluate("nmap -sS -p 1-1024 192.168.1.5", case, {"status": "success", "tool": "nmap"}, status_code=200)
        self.assertTrue(res_range["ports_preserved"])

        # All-ports flag -p-
        res_all = self.validator.evaluate("nmap -sS -p- 192.168.1.5", case, {"status": "success", "tool": "nmap"}, status_code=200)
        self.assertTrue(res_all["ports_preserved"])

    def test_wrong_option_values_fail(self):
        case = {
            "id": "TEST-005",
            "name": "Extension and thread options validation",
            "expected_tool": "gobuster",
            "expect_success": True,
            "expected_semantics": {
                "executable": "gobuster",
                "target_value": "192.168.1.50",
                "expected_ports": [80]
            },
            "body": {
                "intent_contract": {
                    "intent": "DIRECTORY_BRUTEFORCE",
                    "target": {"type": "URL", "value": "192.168.1.50"},
                    "modifiers": ["extension:php,html", "threads:20"]
                }
            }
        }
        # Missing html extension and wrong thread count (10 instead of 20)
        res = self.validator.evaluate("gobuster dir -u http://192.168.1.50 -w wordlist.txt -x php -t 10", case, {"status": "success", "tool": "gobuster"}, status_code=200)
        self.assertFalse(res["options_valid"])
        self.assertFalse(res["semantically_correct"])

    def test_gobuster_dns_mode_handled_separately(self):
        case = {
            "id": "TEST-006",
            "name": "Gobuster DNS mode expects -d and domain target target0.local",
            "expected_tool": "gobuster",
            "expect_success": True,
            "expected_semantics": {
                "executable": "gobuster",
                "target_value": "target0.local",
                "expected_ports": []
            },
            "body": {
                "intent_contract": {
                    "intent": "DIRECTORY_BRUTEFORCE",
                    "target": {"type": "DOMAIN", "value": "target0.local"},
                    "modifiers": ["dns"]
                }
            }
        }
        # 1. Assert dir mode fails when dns mode is requested
        res_dir = self.validator.evaluate("gobuster dir -u http://target0.local -w words.txt", case, {"status": "success", "tool": "gobuster"}, status_code=200)
        self.assertFalse(res_dir["tool_correct"])

        # 2. Assert DNS mode correctly parses executable/subcommand, target, and flags
        res_dns = self.validator.evaluate("gobuster dns -d target0.local -w words.txt", case, {"status": "success", "tool": "gobuster"}, status_code=200)
        self.assertTrue(res_dns["tool_correct"])
        self.assertTrue(res_dns["target_preserved"])
        self.assertTrue(res_dns["semantics_valid"])

        # 3. Assert real unmodified SafetyFilter blocks target0.local and flags scope violation
        self.assertFalse(res_dns["safety_valid"])
        self.assertFalse(res_dns["semantically_correct"])
        self.assertTrue(any("target0.local is not RFC-1918 private range" in issue for issue in res_dns["details"]))

    def test_gobuster_dns_mode_parser_only_with_mocked_safety(self):
        """PARSER-ONLY TEST: Verifies pure AST parser and semantics handling independently from production safety filter."""
        case = {
            "id": "TEST-006-PARSER-ONLY",
            "name": "Gobuster DNS mode parser check with mocked safety filter",
            "expected_tool": "gobuster",
            "expect_success": True,
            "expected_semantics": {
                "executable": "gobuster",
                "target_value": "target0.local",
                "expected_ports": []
            },
            "body": {
                "intent_contract": {
                    "intent": "DIRECTORY_BRUTEFORCE",
                    "target": {"type": "DOMAIN", "value": "target0.local"},
                    "modifiers": ["dns"]
                }
            }
        }
        with patch.object(self.validator.safety_filter, 'validate', return_value=(True, [])):
            res_dns = self.validator.evaluate("gobuster dns -d target0.local -w words.txt", case, {"status": "success", "tool": "gobuster"}, status_code=200)
            self.assertTrue(res_dns["tool_correct"])
            self.assertTrue(res_dns["target_preserved"])
            self.assertTrue(res_dns["semantics_valid"])
            self.assertTrue(res_dns["safety_valid"])
            self.assertTrue(res_dns["semantically_correct"])

    def test_strict_rejection_checks(self):
        """Strictly requires expected HTTP status code and exact error reason match. Rejects HTTP 500 or wrong reasons."""
        case = {
            "id": "TEST-007",
            "name": "Public IP rejection case",
            "expect_success": False,
            "expected_semantics": {
                "expected_status_code": 400,
                "expected_error_substring": "BLOCKED: target 8.8.8.8 is not RFC-1918 private range"
            }
        }
        # 1. HTTP 500 server crash must NOT satisfy expected HTTP 400 rejection
        res_500 = self.validator.evaluate("", case, {"status": "error", "detail": "Internal Server Error"}, status_code=500)
        self.assertFalse(res_500["status_code_correct"])
        self.assertFalse(res_500["semantically_correct"])

        # 2. Wrong rejection reason must NOT satisfy expected error reason
        res_wrong_reason = self.validator.evaluate("", case, {"status": "error", "detail": "INTENT_REJECTED: Out of scope request"}, status_code=400)
        self.assertTrue(res_wrong_reason["status_code_correct"])
        self.assertFalse(res_wrong_reason["safety_valid"])
        self.assertFalse(res_wrong_reason["semantically_correct"])

        # 3. HTTP 200 success for a rejection case must fail
        res_200 = self.validator.evaluate("nmap 8.8.8.8", case, {"status": "success", "command": "nmap 8.8.8.8"}, status_code=200)
        self.assertFalse(res_200["status_code_correct"])
        self.assertFalse(res_200["safety_valid"])
        self.assertFalse(res_200["semantically_correct"])

        # 4. Exact match of HTTP 400 and exact error reason succeeds
        res_pass = self.validator.evaluate("", case, {"status": "error", "detail": "BLOCKED: target 8.8.8.8 is not RFC-1918 private range"}, status_code=400)
        self.assertTrue(res_pass["status_code_correct"])
        self.assertTrue(res_pass["safety_valid"])
        self.assertTrue(res_pass["semantically_correct"])

    def test_strict_scan_semantics(self):
        """Timing alone does NOT satisfy SYN scan, and host discovery -sn does NOT satisfy port scan."""
        case_syn = {
            "id": "TEST-008A",
            "expected_tool": "nmap",
            "expect_success": True,
            "expected_semantics": {
                "executable": "nmap",
                "target_value": "192.168.1.5",
                "expected_flags": ["-sS", "-T2"]
            },
            "body": {
                "intent_contract": {
                    "intent": "NETWORK_SCAN",
                    "target": {"type": "IP", "value": "192.168.1.5"},
                    "modifiers": ["stealth"]
                }
            }
        }
        # Timing -T2 alone without -sS or -sT fails SYN scan requirement when -sS in expected_flags
        res_syn_fail = self.validator.evaluate("nmap -T2 192.168.1.5", case_syn, {"status": "success", "tool": "nmap"}, status_code=200)
        self.assertFalse(res_syn_fail["semantics_valid"])

        case_fast = {
            "id": "TEST-008B",
            "expected_tool": "nmap",
            "expect_success": True,
            "expected_semantics": {
                "executable": "nmap",
                "target_value": "192.168.1.5",
                "expected_flags": ["-F"]
            },
            "body": {
                "intent_contract": {
                    "intent": "NETWORK_SCAN",
                    "target": {"type": "IP", "value": "192.168.1.5"},
                    "modifiers": ["fast"]
                }
            }
        }
        # Host discovery -sn does NOT satisfy fast port scan -F
        res_fast_fail = self.validator.evaluate("nmap -sn 192.168.1.5", case_fast, {"status": "success", "tool": "nmap"}, status_code=200)
        self.assertFalse(res_fast_fail["semantics_valid"])

    def test_session_target_recovery_setup_and_evaluation(self):
        sess_mgr = SessionContextManager()
        test_session_id = f"test-eval-rec-{uuid.uuid4()}"
        self.addCleanup(sess_mgr.clear_session, test_session_id)

        # 1. Update session to simulate prerequisite
        sess_mgr.update_session(test_session_id, "nmap -sS 192.168.1.50", "nmap", "192.168.1.50")
        recovered = sess_mgr.get_last_target(test_session_id)
        self.assertEqual(recovered, "192.168.1.50")

        # 2. Evaluate case using recovered target
        case = {
            "id": "BENCH-024",
            "name": "Target recovery test",
            "expected_tool": "nmap",
            "expect_success": True,
            "expected_semantics": {
                "executable": "nmap",
                "target_value": recovered,
                "expected_ports": []
            },
            "body": {
                "intent_contract": {
                    "intent": "NETWORK_SCAN",
                    "target": {"type": "IP", "value": "UNKNOWN"},
                    "modifiers": ["stealth"]
                },
                "session_id": test_session_id
            }
        }
    def test_gobuster_ssl_http_with_k_fails(self):
        """Gobuster -k with http:// URL MUST FAIL the SSL modifier requirement."""
        case = {
            "id": "TEST-SSL-001",
            "expected_tool": "gobuster",
            "expect_success": True,
            "expected_semantics": {"executable": "gobuster", "target_value": "192.168.1.50", "expected_ports": [443]},
            "body": {
                "intent_contract": {
                    "intent": "DIRECTORY_BRUTEFORCE",
                    "target": {"type": "URL", "value": "192.168.1.50"},
                    "ports": [443],
                    "modifiers": ["ssl", "silent"]
                }
            }
        }
        # http:// scheme with -k is NOT HTTPS
        res_fail = self.validator.evaluate("gobuster dir -u http://192.168.1.50 -w wordlist.txt -k -q", case, {"status": "success", "tool": "gobuster"}, status_code=200)
        self.assertFalse(res_fail["semantics_valid"])
        self.assertFalse(res_fail["semantically_correct"])

        # https:// scheme passes SSL requirement
        res_pass = self.validator.evaluate("gobuster dir -u https://192.168.1.50 -w wordlist.txt -k -q", case, {"status": "success", "tool": "gobuster"}, status_code=200)
        self.assertTrue(res_pass["semantics_valid"])
        self.assertTrue(res_pass["semantically_correct"])

    def test_nmap_target_ignores_iL_filename(self):
        """Nmap -iL filename must NOT be counted as literal target preservation."""
        case = {
            "id": "TEST-IL-001",
            "expected_tool": "nmap",
            "expect_success": True,
            "expected_semantics": {"executable": "nmap", "target_value": "192.168.1.5", "expected_ports": []},
            "body": {
                "intent_contract": {
                    "intent": "NETWORK_SCAN",
                    "target": {"type": "IP", "value": "192.168.1.5"},
                    "modifiers": []
                }
            }
        }
        # IP 192.168.1.5 is ONLY in -iL filename, positional target is 192.168.1.99
        res = self.validator.evaluate("nmap -sS -iL /tmp/192.168.1.5.txt 192.168.1.99", case, {"status": "success", "tool": "nmap"}, status_code=200)
        self.assertFalse(res["target_preserved"])

    def test_aggressive_and_os_detection_scan_semantics(self):
        """Aggressive modifier requires -A, os-detection requires -O or -A."""
        case = {
            "id": "TEST-MOD-001",
            "expected_tool": "nmap",
            "expect_success": True,
            "expected_semantics": {"executable": "nmap", "target_value": "192.168.1.5", "expected_ports": []},
            "body": {
                "intent_contract": {
                    "intent": "NETWORK_SCAN",
                    "target": {"type": "IP", "value": "192.168.1.5"},
                    "modifiers": ["aggressive", "os-detection"]
                }
            }
        }
        # Command missing -A / -O fails
        res_fail = self.validator.evaluate("nmap -sS 192.168.1.5", case, {"status": "success", "tool": "nmap"}, status_code=200)
        self.assertFalse(res_fail["semantics_valid"])

        # Command with -A passes both
        res_pass = self.validator.evaluate("nmap -A 192.168.1.5", case, {"status": "success", "tool": "nmap"}, status_code=200)
        self.assertTrue(res_pass["semantics_valid"])

if __name__ == "__main__":
    unittest.main()
