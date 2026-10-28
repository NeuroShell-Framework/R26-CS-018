"""
Unit tests for NeuroShell Component 2 (C2) Final SFT Dataset Preparation Pipeline.
Uses standard unittest framework for maximum compatibility.
"""

import os
import json
import unittest
import pandas as pd
from scripts.prepare_c2_sft_dataset import (
    normalize_whitespace,
    normalize_command_text,
    extract_executable_tool,
    validate_and_filter_records,
    deduplicate_records,
    perform_grouped_stratified_split,
    run_pipeline,
    SUPPORTED_TOOLS,
    OUTPUT_DIR,
)


class TestC2SFTDatasetPipeline(unittest.TestCase):

    def test_normalize_whitespace(self):
        raw = "  Goal:   perform  network  scan   on 10.0.0.1  \n "
        normalized = normalize_whitespace(raw)
        self.assertEqual(normalized, "Goal: perform network scan on 10.0.0.1")

    def test_normalize_command_text_preserves_semantics(self):
        # Semicolons, pipes, redirects, flags must be preserved exactly
        cmd_raw = "  nmap -sS -p 80 10.0.0.1 ; echo 'done' | tee /tmp/log.txt  "
        cmd_norm = normalize_command_text(cmd_raw)
        self.assertEqual(cmd_norm, "nmap -sS -p 80 10.0.0.1 ; echo 'done' | tee /tmp/log.txt")

    def test_extract_executable_tool(self):
        self.assertEqual(extract_executable_tool("nmap -sS 10.0.0.1"), "nmap")
        self.assertEqual(extract_executable_tool("sudo nmap -A 10.0.0.1"), "nmap")
        self.assertEqual(extract_executable_tool("/usr/bin/gobuster dir -u http://example.com -w words.txt"), "gobuster")
        self.assertEqual(extract_executable_tool("./nikto.pl -h 10.0.0.1"), "nikto")

    def test_rejection_rules(self):
        sample_records = [
            # Valid
            {
                "prompt": "Scan target for open ports",
                "expected_command": "nmap -p 80,443 10.0.0.1",
                "tool": "nmap",
            },
            # Empty prompt
            {
                "prompt": "",
                "expected_command": "nmap -p 80 10.0.0.1",
                "tool": "nmap",
            },
            # Empty command
            {
                "prompt": "Scan target",
                "expected_command": "",
                "tool": "nmap",
            },
            # Unsupported tool
            {
                "prompt": "Brute force SSH",
                "expected_command": "hydra -l admin -P pass.txt 10.0.0.1 ssh",
                "tool": "hydra",
            },
            # Tool/command mismatch
            {
                "prompt": "Directory brute force",
                "expected_command": "gobuster dir -u http://10.0.0.1 -w words.txt",
                "tool": "nmap",  # Declared nmap but command is gobuster
            },
        ]

        valid, rejections = validate_and_filter_records(sample_records)
        self.assertEqual(len(valid), 1)
        self.assertEqual(valid[0]["tool"], "nmap")
        self.assertEqual(rejections["EMPTY_PROMPT"], 1)
        self.assertEqual(rejections["EMPTY_COMMAND"], 1)
        self.assertEqual(rejections["UNSUPPORTED_TOOL"], 1)
        self.assertEqual(rejections["TOOL_COMMAND_MISMATCH"], 1)

    def test_cross_source_deduplication_and_provenance(self):
        records = [
            {
                "source": "pentest_r1",
                "source_record_id": "PR1-001",
                "prompt": "Scan target 10.0.0.1",
                "expected_command": "nmap -F 10.0.0.1",
                "tool": "nmap",
            },
            {
                "source": "researcher_curated",
                "source_record_id": "REC-001",
                "prompt": "Scan target 10.0.0.1",  # Same prompt + command
                "expected_command": "nmap -F 10.0.0.1",
                "tool": "nmap",
            },
            {
                "source": "pentest_r1",
                "source_record_id": "PR1-002",
                "prompt": "Scan target 10.0.0.2",
                "expected_command": "nmap -F 10.0.0.2",
                "tool": "nmap",
            },
        ]

        deduped, metrics = deduplicate_records(records)
        self.assertEqual(len(deduped), 2)
        self.assertEqual(metrics["total_duplicates_removed"], 1)
        self.assertEqual(metrics["cross_source_duplicates"], 1)

        canonical = deduped[0]
        self.assertEqual(canonical["source"], "pentest_r1")
        self.assertEqual(len(canonical["secondary_provenance"]), 1)
        self.assertEqual(canonical["secondary_provenance"][0]["source"], "researcher_curated")
        self.assertEqual(canonical["secondary_provenance"][0]["source_record_id"], "REC-001")

    def test_grouped_stratified_split_and_no_leakage(self):
        # Construct synthetic dataset with command repeats across multiple prompts
        records = []
        tools = ["nmap", "gobuster", "nikto"]
        for i in range(120):
            t = tools[i % 3]
            cmd = f"{t} --flag-{i//10} target.com"
            records.append({
                "prompt": f"Prompt {i} for {t}",
                "expected_command": cmd,
                "tool": t,
            })

        train, val, test = perform_grouped_stratified_split(records, seed=42)

        total = len(train) + len(val) + len(test)
        self.assertEqual(total, len(records))

        train_cmds = set(r["expected_command"].lower() for r in train)
        val_cmds = set(r["expected_command"].lower() for r in val)
        test_cmds = set(r["expected_command"].lower() for r in test)

        # Verify ZERO command leakage across splits
        self.assertEqual(len(train_cmds.intersection(val_cmds)), 0)
        self.assertEqual(len(train_cmds.intersection(test_cmds)), 0)
        self.assertEqual(len(val_cmds.intersection(test_cmds)), 0)

        # Verify all tools present in each split
        for split_recs, split_name in [(train, "train"), (val, "val"), (test, "test")]:
            split_tools = set(r["tool"] for r in split_recs)
            self.assertTrue(SUPPORTED_TOOLS.issubset(split_tools), f"Missing tools in {split_name} split!")

    def test_full_pipeline_execution(self):
        manifest = run_pipeline()

        self.assertTrue(os.path.exists(os.path.join(OUTPUT_DIR, "c2_sft_full.csv")))
        self.assertTrue(os.path.exists(os.path.join(OUTPUT_DIR, "c2_sft_train.csv")))
        self.assertTrue(os.path.exists(os.path.join(OUTPUT_DIR, "c2_sft_validation.csv")))
        self.assertTrue(os.path.exists(os.path.join(OUTPUT_DIR, "c2_sft_test.csv")))
        self.assertTrue(os.path.exists(os.path.join(OUTPUT_DIR, "c2_sft_manifest.json")))

        self.assertEqual(
            manifest["final_unique_total"],
            manifest["splits"]["train"]["count"] +
            manifest["splits"]["validation"]["count"] +
            manifest["splits"]["test"]["count"]
        )

        self.assertFalse(manifest["leakage_verification"]["command_leakage_detected"])


if __name__ == "__main__":
    unittest.main()
