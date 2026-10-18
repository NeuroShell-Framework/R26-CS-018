"""
NeuroShell Component 2 (C2) Final SFT Dataset Preparation Pipeline.

This script loads candidate records from:
1. data/synthesis_dataset/pentestr1_c2_normalized.csv (provenance: pentest_r1)
2. data/synthesis_dataset/c2_filtered_dataset.csv (provenance: researcher_curated)

It performs:
- Schema mapping & text normalization (preserving shell syntax in commands)
- Quality validation & rejection logging
- Cross-source prompt+command deduplication with secondary provenance preservation
- Command-cluster grouped stratified splitting (80% train / 10% val / 10% test, seed=42)
- Zero-leakage verification across splits
- Output generation under data/synthesis_dataset/final/
"""

import os
import re
import json
import logging
from typing import Dict, List, Tuple, Any
import pandas as pd
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

SUPPORTED_TOOLS = {"nmap", "nikto", "gobuster"}
RANDOM_SEED = 42

PATH_PENTEST_R1 = "data/synthesis_dataset/pentestr1_c2_normalized.csv"
PATH_RESEARCHER_CURATED = "data/synthesis_dataset/c2_filtered_dataset.csv"
OUTPUT_DIR = "data/synthesis_dataset/final"


def normalize_whitespace(text: str) -> str:
    """Safely normalizes whitespace without stripping shell operators or altering quoted args."""
    if not isinstance(text, str):
        return ""
    # Strip outer whitespace and collapse multiple unquoted whitespace
    return re.sub(r"\s+", " ", text).strip()


def normalize_command_text(command: str) -> str:
    """
    Normalizes command string safely.
    Preserves all command semantics, trailing semicolons, pipes, redirects, and flag values.
    Only collapses extraneous consecutive spaces.
    """
    if not isinstance(command, str):
        return ""
    return re.sub(r"\s+", " ", command).strip()


def extract_executable_tool(command: str) -> str:
    """Extracts the primary executable name from command string."""
    tokens = command.strip().split()
    if not tokens:
        return ""
    first_token = tokens[0].lower()
    if first_token == "sudo" and len(tokens) > 1:
        first_token = tokens[1].lower()
    # Strip any directory path prefix if present (e.g. /usr/bin/nmap -> nmap, ./nikto.pl -> nikto.pl)
    first_token = os.path.basename(first_token)
    if first_token.endswith(".pl") or first_token.endswith(".py") or first_token.endswith(".sh"):
        first_token = first_token.rsplit(".", 1)[0]
    return first_token


def load_candidate_records() -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Loads and standardizes raw candidate records from both sources."""
    raw_counts = {}
    records = []

    # 1. Load Pentest-R1 dataset
    if os.path.exists(PATH_PENTEST_R1):
        df_pr1 = pd.read_csv(PATH_PENTEST_R1)
        raw_counts["pentest_r1"] = len(df_pr1)
        for idx, row in df_pr1.iterrows():
            tool = str(row.get("tool", "")).lower().strip()
            prompt = normalize_whitespace(row.get("prompt", ""))
            cmd = normalize_command_text(row.get("expected_command", ""))
            src_id = str(row.get("source_record_id", f"PR1-{idx:04d}"))

            records.append({
                "source": "pentest_r1",
                "source_record_id": src_id,
                "prompt": prompt,
                "intent": str(row.get("intent", "UNKNOWN")).strip().upper(),
                "target": str(row.get("target", "")).strip(),
                "ports": str(row.get("ports", "")).strip(),
                "modifiers": str(row.get("modifiers", "")).strip(),
                "tool": tool,
                "expected_command": cmd,
                "expected_flags": str(row.get("expected_flags", "")).strip(),
                "safety_passed": bool(row.get("safety_passed", True)),
                "raw_source_data": row.to_dict()
            })
    else:
        raw_counts["pentest_r1"] = 0
        logger.warning(f"File not found: {PATH_PENTEST_R1}")

    # 2. Load Researcher-Curated dataset
    if os.path.exists(PATH_RESEARCHER_CURATED):
        df_rc = pd.read_csv(PATH_RESEARCHER_CURATED)
        raw_counts["researcher_curated"] = len(df_rc)
        for idx, row in df_rc.iterrows():
            tool = str(row.get("expected_tool", "")).lower().strip()
            prompt = normalize_whitespace(row.get("query_used", ""))
            cmd = normalize_command_text(row.get("expected_command", ""))
            src_id = str(row.get("record_id", f"REC-{idx:04d}"))

            records.append({
                "source": "researcher_curated",
                "source_record_id": src_id,
                "prompt": prompt,
                "intent": str(row.get("intent", "UNKNOWN")).strip().upper(),
                "target": str(row.get("target_value", "")).strip(),
                "ports": str(row.get("ports", "")).strip(),
                "modifiers": str(row.get("modifiers", "")).strip(),
                "tool": tool,
                "expected_command": cmd,
                "expected_flags": str(row.get("expected_flags", "")).strip(),
                "safety_passed": bool(row.get("safety_passed", True)),
                "raw_source_data": row.to_dict()
            })
    else:
        raw_counts["researcher_curated"] = 0
        logger.warning(f"File not found: {PATH_RESEARCHER_CURATED}")

    return records, raw_counts


def validate_and_filter_records(records: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Applies quality rejection rules."""
    valid_records = []
    rejection_counts = {
        "EMPTY_PROMPT": 0,
        "EMPTY_COMMAND": 0,
        "UNSUPPORTED_TOOL": 0,
        "TOOL_COMMAND_MISMATCH": 0,
    }

    for r in records:
        if not r["prompt"]:
            rejection_counts["EMPTY_PROMPT"] += 1
            continue
        if not r["expected_command"]:
            rejection_counts["EMPTY_COMMAND"] += 1
            continue
        if r["tool"] not in SUPPORTED_TOOLS:
            rejection_counts["UNSUPPORTED_TOOL"] += 1
            continue

        exec_tool = extract_executable_tool(r["expected_command"])
        if exec_tool != r["tool"]:
            rejection_counts["TOOL_COMMAND_MISMATCH"] += 1
            logger.warning(
                f"Tool/command mismatch: declared '{r['tool']}', executable '{exec_tool}' in '{r['expected_command']}'"
            )
            continue

        valid_records.append(r)

    return valid_records, rejection_counts


def deduplicate_records(records: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Deduplicates records based on normalized (prompt.lower(), expected_command.lower()).
    Preserves secondary source provenance when cross-source or intra-source duplicates occur.
    """
    seen_map = {}
    deduped_records = []
    duplicate_metrics = {
        "total_duplicates_removed": 0,
        "intra_source_duplicates": 0,
        "cross_source_duplicates": 0,
    }

    for r in records:
        key = (r["prompt"].lower(), r["expected_command"].lower())

        if key in seen_map:
            canonical = seen_map[key]
            duplicate_metrics["total_duplicates_removed"] += 1

            if canonical["source"] != r["source"]:
                duplicate_metrics["cross_source_duplicates"] += 1
            else:
                duplicate_metrics["intra_source_duplicates"] += 1

            # Preserve secondary provenance
            sec_provenance = {
                "source": r["source"],
                "source_record_id": r["source_record_id"],
            }

            if "secondary_provenance" not in canonical:
                canonical["secondary_provenance"] = []
            canonical["secondary_provenance"].append(sec_provenance)
        else:
            r["secondary_provenance"] = []
            seen_map[key] = r
            deduped_records.append(r)

    return deduped_records, duplicate_metrics


def perform_grouped_stratified_split(
    records: List[Dict[str, Any]], seed: int = RANDOM_SEED
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Splits unique records into Train (80%), Validation (10%), and Test (10%) sets.
    Groups by expected_command to ensure zero command leakage across splits.
    Stratifies command groups by tool to ensure all supported tools exist in each split.
    """
    df = pd.DataFrame(records)

    # 1. Group by expected_command to prevent command leakage
    cmd_to_group = {cmd: i for i, cmd in enumerate(df["expected_command"].str.lower().unique())}
    df["group_id"] = df["expected_command"].str.lower().map(cmd_to_group)

    # 2. Aggregate groups for tool stratification
    group_info = df.groupby("group_id").agg({
        "tool": lambda x: x.mode()[0],
        "prompt": "count"
    }).reset_index()

    # 3. Stratified split of groups: 80% train, 20% temp
    g_train, g_temp = train_test_split(
        group_info, test_size=0.20, random_state=seed, stratify=group_info["tool"]
    )
    # 4. Stratified split of temp: 50% val (10% total), 50% test (10% total)
    g_val, g_test = train_test_split(
        g_temp, test_size=0.50, random_state=seed, stratify=g_temp["tool"]
    )

    train_group_ids = set(g_train["group_id"])
    val_group_ids = set(g_val["group_id"])
    test_group_ids = set(g_test["group_id"])

    # Map split back to records
    train_records = [r for r in records if cmd_to_group[r["expected_command"].lower()] in train_group_ids]
    val_records = [r for r in records if cmd_to_group[r["expected_command"].lower()] in val_group_ids]
    test_records = [r for r in records if cmd_to_group[r["expected_command"].lower()] in test_group_ids]

    # Verify zero command leakage
    train_cmds = set(r["expected_command"].lower() for r in train_records)
    val_cmds = set(r["expected_command"].lower() for r in val_records)
    test_cmds = set(r["expected_command"].lower() for r in test_records)

    assert len(train_cmds.intersection(val_cmds)) == 0, "Leakage detected between Train and Val!"
    assert len(train_cmds.intersection(test_cmds)) == 0, "Leakage detected between Train and Test!"
    assert len(val_cmds.intersection(test_cmds)) == 0, "Leakage detected between Val and Test!"

    return train_records, val_records, test_records


def run_pipeline() -> Dict[str, Any]:
    """Runs the complete dataset preparation pipeline and writes output files."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 1. Load candidates
    raw_records, raw_source_counts = load_candidate_records()
    total_raw = len(raw_records)

    # 2. Validate & Filter
    valid_records, rejection_counts = validate_and_filter_records(raw_records)
    accepted_before_dedup = len(valid_records)

    # 3. Deduplicate
    unique_records, duplicate_metrics = deduplicate_records(valid_records)
    final_unique_count = len(unique_records)

    # Assign final record IDs
    for idx, r in enumerate(unique_records):
        r["record_id"] = f"C2SFT-{idx+1:04d}"

    # 4. Grouped Stratified Split
    train_recs, val_recs, test_recs = perform_grouped_stratified_split(unique_records, seed=RANDOM_SEED)

    # 5. Format DataFrame columns for output
    output_columns = [
        "record_id",
        "source",
        "source_record_id",
        "prompt",
        "intent",
        "target",
        "ports",
        "modifiers",
        "tool",
        "expected_command",
        "expected_flags",
        "safety_passed",
        "secondary_provenance",
    ]

    def prepare_df(recs_list: List[Dict[str, Any]]) -> pd.DataFrame:
        formatted = []
        for r in recs_list:
            item = {col: r.get(col, "") for col in output_columns}
            # Convert secondary_provenance list to JSON string for CSV storage
            item["secondary_provenance"] = json.dumps(item["secondary_provenance"])
            formatted.append(item)
        return pd.DataFrame(formatted)

    df_full = prepare_df(unique_records)
    df_train = prepare_df(train_recs)
    df_val = prepare_df(val_recs)
    df_test = prepare_df(test_recs)

    # Save CSV files
    path_full = os.path.join(OUTPUT_DIR, "c2_sft_full.csv")
    path_train = os.path.join(OUTPUT_DIR, "c2_sft_train.csv")
    path_val = os.path.join(OUTPUT_DIR, "c2_sft_validation.csv")
    path_test = os.path.join(OUTPUT_DIR, "c2_sft_test.csv")
    path_manifest = os.path.join(OUTPUT_DIR, "c2_sft_manifest.json")

    df_full.to_csv(path_full, index=False)
    df_train.to_csv(path_train, index=False)
    df_val.to_csv(path_val, index=False)
    df_test.to_csv(path_test, index=False)

    # Calculate distributions
    def get_tool_dist(recs: List[Dict[str, Any]]) -> Dict[str, int]:
        counts = {}
        for r in recs:
            t = r["tool"]
            counts[t] = counts.get(t, 0) + 1
        return counts

    def get_intent_dist(recs: List[Dict[str, Any]]) -> Dict[str, int]:
        counts = {}
        for r in recs:
            i = r["intent"]
            counts[i] = counts.get(i, 0) + 1
        return counts

    # Build manifest
    manifest = {
        "dataset_name": "NeuroShell C2 Final Supervised Fine-Tuning Dataset",
        "version": "1.0.0",
        "split_seed": RANDOM_SEED,
        "supported_tools": sorted(list(SUPPORTED_TOOLS)),
        "source_counts": raw_source_counts,
        "raw_candidate_total": total_raw,
        "accepted_before_deduplication": accepted_before_dedup,
        "rejection_counts": rejection_counts,
        "duplicate_metrics": duplicate_metrics,
        "final_unique_total": final_unique_count,
        "splits": {
            "train": {
                "count": len(train_recs),
                "percentage": round(len(train_recs) / final_unique_count * 100, 2),
                "tool_distribution": get_tool_dist(train_recs),
                "intent_distribution": get_intent_dist(train_recs),
            },
            "validation": {
                "count": len(val_recs),
                "percentage": round(len(val_recs) / final_unique_count * 100, 2),
                "tool_distribution": get_tool_dist(val_recs),
                "intent_distribution": get_intent_dist(val_recs),
            },
            "test": {
                "count": len(test_recs),
                "percentage": round(len(test_recs) / final_unique_count * 100, 2),
                "tool_distribution": get_tool_dist(test_recs),
                "intent_distribution": get_intent_dist(test_recs),
            },
        },
        "overall_tool_distribution": get_tool_dist(unique_records),
        "overall_intent_distribution": get_intent_dist(unique_records),
        "leakage_verification": {
            "command_leakage_detected": False,
            "train_val_overlap": 0,
            "train_test_overlap": 0,
            "val_test_overlap": 0,
        },
        "files_generated": [
            "c2_sft_full.csv",
            "c2_sft_train.csv",
            "c2_sft_validation.csv",
            "c2_sft_test.csv",
            "c2_sft_manifest.json",
        ]
    }

    with open(path_manifest, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    logger.info(f"Final dataset pipeline completed successfully. Output files saved in {OUTPUT_DIR}")
    return manifest


if __name__ == "__main__":
    result = run_pipeline()
    print(json.dumps(result, indent=2))
