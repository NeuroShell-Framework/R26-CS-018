"""
Regression unit tests for NeuroShell Component 2 (C2) Final SFT Pipeline.
Tests parser-aware validation logic, trailing prose recovery, placeholder filtering,
malformed target detection, flag validation, and safety filters.
"""

import unittest
from scripts.c2_sft_final_pipeline import (
    validate_command_string,
    extract_command_prefix,
    evaluate_record_for_sft,
    build_c2_sft_example,
    is_malformed_target,
    PLACEHOLDER_REGEX
)


class TestSFTFinalPipelineRegression(unittest.TestCase):

    def test_valid_http_https_gobuster_commands(self):
        """Verify that valid Gobuster commands with HTTP and HTTPS URLs are accepted."""
        cmds = [
            "gobuster dir --url http://10.129.147.195/ --wordlist /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt -t 50",
            "gobuster dir --url https://laboratory.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 30 -k --no-error",
            "gobuster dir -u http://10.0.105.42/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H \"Authorization: Bearer token123\"",
            "gobuster vhost -u http://10.129.98.125 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
            "gobuster fuzz -u https://10.0.210.99/index.php?FUZZ=test -w /usr/share/wordlists/dirb/common.txt -k"
        ]

        for cmd in cmds:
            valid, reasons = validate_command_string(cmd, "gobuster")
            self.assertTrue(valid, f"Failed validation for valid Gobuster command: {cmd}, reasons: {reasons}")

    def test_valid_nikto_url_targets(self):
        """Verify that valid Nikto URL and IP targets are accepted."""
        cmds = [
            "nikto -h http://10.129.204.187/",
            "nikto -h http://10.129.204.187:8080/",
            "nikto -h 10.0.135.83",
            "nikto -h http://webmail.chaos.htb"
        ]

        for cmd in cmds:
            valid, reasons = validate_command_string(cmd, "nikto")
            self.assertTrue(valid, f"Failed validation for valid Nikto command: {cmd}, reasons: {reasons}")

    def test_valid_nmap_commands(self):
        """Verify that valid Nmap commands are accepted."""
        cmds = [
            "nmap -sC -sV 10.129.147.195",
            "nmap -p 22,80 -sC -sV 10.129.147.195",
            "nmap -p- --min-rate 10000 10.129.147.195",
            "nmap -sC -sV blunder.htb"
        ]

        for cmd in cmds:
            valid, reasons = validate_command_string(cmd, "nmap")
            self.assertTrue(valid, f"Failed validation for valid Nmap command: {cmd}, reasons: {reasons}")

    def test_commands_with_genuine_appended_explanations(self):
        """Verify that commands with trailing explanatory prose are recovered properly."""
        test_cases = [
            (
                "gobuster dir -u http://192.168.56.105 -w /usr/share/wordlists/dirb/common.txt: Este comando se utiliza para realizar un escaneo de directorios en la URL dada (-u) con la palabra clave común (-w).",
                "gobuster",
                "gobuster dir -u http://192.168.56.105 -w /usr/share/wordlists/dirb/common.txt"
            ),
            (
                "gobuster dir -u http://192.168.10.177 -w /usr/share/wordlists/dirb/common.txt (this command is used to brute force directories on the target web application)",
                "gobuster",
                "gobuster dir -u http://192.168.10.177 -w /usr/share/wordlists/dirb/common.txt"
            ),
            (
                "nmap -A 10.10.10.10: This command is used to perform a comprehensive scan of the target IP address using nmap.",
                "nmap",
                "nmap -A 10.10.10.10"
            )
        ]

        for raw_cmd, tool, expected_clean in test_cases:
            rec = {"command": raw_cmd, "tool": tool, "subintent_guess": "scan"}
            status, canonical_cmd, transform_reason, reasons = evaluate_record_for_sft(rec)
            self.assertEqual(status, "RECOVERED")
            self.assertEqual(canonical_cmd, expected_clean)
            self.assertIsNotNone(transform_reason)

    def test_malformed_placeholder_targets(self):
        """Verify that placeholder targets are strictly rejected."""
        placeholder_cmds = [
            ("gobuster dir -u [url] -w [diccionario]", "gobuster"),
            ("gobuster dir -u http://$TARGET_IP -w words.txt", "gobuster"),
            ("nikto -h [target_host]", "nikto"),
            ("nikto -h [host URL]", "nikto"),
            ("nmap -p 80 [target_ip]", "nmap"),
            ("nmap -sS example.com", "nmap"),
            ("gobuster dns -d example.com -w words.txt", "gobuster")
        ]

        for cmd, tool in placeholder_cmds:
            valid, reasons = validate_command_string(cmd, tool)
            self.assertFalse(valid, f"Placeholder command incorrectly accepted: {cmd}")
            self.assertTrue(any("PLACEHOLDER" in r for r in reasons))

    def test_invalid_cli_syntax(self):
        """Verify that invalid CLI syntax, missing targets, or malformed flags are rejected."""
        invalid_cmds = [
            ("nmap T4 sC sV p 101011164", "nmap"),  # Missing option hyphens
            ("nikto -h //192.168.1.101:8080/", "nikto"),  # Leading double slashes
            ("nikto -h http://192.168.1.110/:", "nikto"),  # Trailing colon without port
            ("gobuster dir -w words.txt", "gobuster"),  # Missing -u/--url
            ("nmap -sS", "nmap")  # Missing target host
        ]

        for cmd, tool in invalid_cmds:
            valid, reasons = validate_command_string(cmd, tool)
            self.assertFalse(valid, f"Invalid CLI syntax incorrectly accepted: {cmd}")

    def test_unsafe_command_forms(self):
        """Verify that unsafe/blocked command forms are rejected by safety filters."""
        unsafe_cmds = [
            ("sudo nmap --script=/tmp/root.nse --interactive", "nmap"),
            ("nmap -sS 10.0.0.1; rm -rf /", "nmap"),
            ("nikto -h http://10.0.0.1 | bash", "nikto")
        ]

        for cmd, tool in unsafe_cmds:
            valid, reasons = validate_command_string(cmd, tool)
            self.assertFalse(valid, f"Unsafe command incorrectly accepted: {cmd}")
            self.assertTrue(any("UNSAFE" in r or "SHLEX" in r for r in reasons))


if __name__ == "__main__":
    unittest.main()
