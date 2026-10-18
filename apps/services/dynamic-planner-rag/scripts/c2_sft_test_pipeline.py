"""
NeuroShell Component 2 (C2) Final TEST SFT Preparation Pipeline.

Applies the exact same record-level preprocessing used by
c2_sft_final_pipeline.py to the untouched held-out test split.

The raw test file is never modified.
"""

import os
import json
from collections import Counter

from scripts.c2_sft_final_pipeline import (
    evaluate_record_for_sft,
    build_c2_sft_example,
    PLACEHOLDER_REGEX,
)


INPUT_TEST = "data/synthesis_dataset/final/c2_sft_test.jsonl"

FINAL_TRAIN = "data/synthesis_dataset/sft_final/c2_train_final.jsonl"
FINAL_VAL = "data/synthesis_dataset/sft_final/c2_validation_final.jsonl"

OUTPUT_DIR = "data/synthesis_dataset/sft_final_test"

OUT_TEST_FINAL = os.path.join(
    OUTPUT_DIR,
    "c2_test_final.jsonl"
)

OUT_REJECTED = os.path.join(
    OUTPUT_DIR,
    "c2_test_final_rejections.jsonl"
)

OUT_TRANSFORMATIONS = os.path.join(
    OUTPUT_DIR,
    "c2_test_final_transformations.jsonl"
)

OUT_REPORT = os.path.join(
    OUTPUT_DIR,
    "c2_test_final_quality_report.txt"
)


def load_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        return [
            json.loads(line)
            for line in f
            if line.strip()
        ]


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    raw_test = load_jsonl(INPUT_TEST)
    train_final = load_jsonl(FINAL_TRAIN)
    val_final = load_jsonl(FINAL_VAL)

    accepted = 0
    recovered = 0
    rejected = 0

    test_final = []
    rejected_records = []
    transformation_records = []

    reason_breakdown = Counter()
    tool_counts = Counter()

    seen_test_commands = set()

    # ---------------------------------------------------
    # Apply SAME final SFT record-level pipeline
    # ---------------------------------------------------

    for idx, record in enumerate(raw_test):

        status, canonical_cmd, transform_reason, reasons = (
            evaluate_record_for_sft(record)
        )

        for reason in reasons:
            reason_key = reason.split(":")[0]
            reason_breakdown[reason_key] += 1

        if status in ["ACCEPT", "RECOVERED"]:

            # Same duplicate-command protection used for training
            if canonical_cmd in seen_test_commands:
                rejected += 1

                reason_breakdown[
                    "INTRA_TEST_DUPLICATE_COMMAND"
                ] += 1

                rejected_records.append({
                    "split": "test",
                    "original_index": idx,
                    "record": record,
                    "rejection_reasons": [
                        "INTRA_TEST_DUPLICATE_COMMAND: "
                        "Command duplicate within test set"
                    ]
                })

                continue

            example = build_c2_sft_example(
                record,
                canonical_cmd,
                transform_reason
                if status == "RECOVERED"
                else None
            )

            seen_test_commands.add(canonical_cmd)

            tool = example["input"]["tool_hint"]
            tool_counts[tool] += 1

            if status == "ACCEPT":
                accepted += 1

            else:
                recovered += 1

                transformation_records.append({
                    "split": "test",
                    "original_index": idx,
                    "original_command": record.get(
                        "command", ""
                    ),
                    "canonical_command": canonical_cmd,
                    "transformation_reason":
                        transform_reason,
                    "provenance":
                        example["provenance"]
                })

            test_final.append(example)

        elif status == "REJECT":

            rejected += 1

            rejected_records.append({
                "split": "test",
                "original_index": idx,
                "record": record,
                "rejection_reasons": reasons
            })

        else:

            rejected += 1
            reason_breakdown["UNKNOWN_STATUS"] += 1

            rejected_records.append({
                "split": "test",
                "original_index": idx,
                "record": record,
                "rejection_reasons": [
                    f"UNKNOWN_STATUS: {status}"
                ]
            })

    # ---------------------------------------------------
    # Integrity verification
    # ---------------------------------------------------

    train_commands = {
        x["output"]["expected_command"]
        for x in train_final
    }

    val_commands = {
        x["output"]["expected_command"]
        for x in val_final
    }

    test_commands = {
        x["output"]["expected_command"]
        for x in test_final
    }

    train_templates = {
        x["provenance"]["semantic_template"]
        for x in train_final
        if x["provenance"].get("semantic_template")
    }

    val_templates = {
        x["provenance"]["semantic_template"]
        for x in val_final
        if x["provenance"].get("semantic_template")
    }

    test_templates = {
        x["provenance"]["semantic_template"]
        for x in test_final
        if x["provenance"].get("semantic_template")
    }

    exact_train_test_overlap = (
        train_commands.intersection(test_commands)
    )

    exact_val_test_overlap = (
        val_commands.intersection(test_commands)
    )

    template_train_test_overlap = (
        train_templates.intersection(test_templates)
    )

    template_val_test_overlap = (
        val_templates.intersection(test_templates)
    )

    invalid_accepted = []

    for idx, example in enumerate(test_final):

        target = example["input"]["target"]["value"]
        command = example["output"]["expected_command"]

        if (
            not target
            or not command
            or PLACEHOLDER_REGEX.search(str(target))
            or PLACEHOLDER_REGEX.search(str(command))
        ):
            invalid_accepted.append({
                "index": idx,
                "target": target,
                "command": command
            })

    # ---------------------------------------------------
    # Save artifacts
    # ---------------------------------------------------

    with open(
        OUT_TEST_FINAL,
        "w",
        encoding="utf-8"
    ) as f:

        for example in test_final:
            f.write(
                json.dumps(
                    example,
                    ensure_ascii=False
                )
                + "\n"
            )

    with open(
        OUT_REJECTED,
        "w",
        encoding="utf-8"
    ) as f:

        for item in rejected_records:
            f.write(
                json.dumps(
                    item,
                    ensure_ascii=False
                )
                + "\n"
            )

    with open(
        OUT_TRANSFORMATIONS,
        "w",
        encoding="utf-8"
    ) as f:

        for item in transformation_records:
            f.write(
                json.dumps(
                    item,
                    ensure_ascii=False
                )
                + "\n"
            )

    final_count = len(test_final)

    report_lines = [
        "=" * 80,
        "NEUROSHELL C2 FINAL HELD-OUT TEST QUALITY REPORT",
        "=" * 80,
        "",
        f"Original Test Records:          {len(raw_test)}",
        f"Directly Accepted:              {accepted}",
        f"Recovered:                      {recovered}",
        f"Rejected:                       {rejected}",
        f"Final Test Set Count:           {final_count}",
        "",
        "COUNTS BY TOOL",
        "-" * 80,
        f"Nmap:                            {tool_counts['nmap']}",
        f"Nikto:                           {tool_counts['nikto']}",
        f"Gobuster:                        {tool_counts['gobuster']}",
        "",
        "REJECTION REASONS",
        "-" * 80,
    ]

    for reason, count in reason_breakdown.most_common():
        report_lines.append(
            f"{reason:<40}: {count}"
        )

    report_lines.extend([
        "",
        "LEAKAGE / INTEGRITY CHECKS",
        "-" * 80,
        f"Exact Train-Test command overlap:      "
        f"{len(exact_train_test_overlap)}",
        f"Exact Validation-Test command overlap: "
        f"{len(exact_val_test_overlap)}",
        f"Train-Test semantic-template overlap:  "
        f"{len(template_train_test_overlap)}",
        f"Val-Test semantic-template overlap:    "
        f"{len(template_val_test_overlap)}",
        f"Invalid accepted samples:              "
        f"{len(invalid_accepted)}",
        "",
        "ARTIFACTS",
        "-" * 80,
        f"Final Test Dataset:       {OUT_TEST_FINAL}",
        f"Rejections Log:           {OUT_REJECTED}",
        f"Transformations Log:      {OUT_TRANSFORMATIONS}",
        f"Quality Report:           {OUT_REPORT}",
        "=" * 80,
    ])

    report_text = "\n".join(report_lines)

    with open(
        OUT_REPORT,
        "w",
        encoding="utf-8"
    ) as f:
        f.write(report_text + "\n")

    print(report_text)

    # Leakage should remain zero for a true held-out split.
    if (
        exact_train_test_overlap
        or exact_val_test_overlap
        or template_train_test_overlap
        or template_val_test_overlap
    ):
        print(
            "\n⚠️ WARNING: Split overlap detected. "
            "Do not run final model evaluation yet."
        )

    elif invalid_accepted:
        print(
            "\n⚠️ WARNING: Invalid accepted samples detected. "
            "Do not run final model evaluation yet."
        )

    else:
        print(
            "\n✅ Test preprocessing completed with "
            "no detected cross-split leakage."
        )


if __name__ == "__main__":
    main()