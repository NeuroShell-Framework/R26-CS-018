#!/usr/bin/env python3
# NeuroShell IRE — Manual Offline CVE Grounding Updater
# Pulls fresh snapshot from CISA KEV feed when run manually by administrator.
# NOTE: MUST NEVER RUN AUTOMATICALLY IN REQUEST PATH OR CI.

import argparse
import json
import sys
from pathlib import Path
import httpx

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_OUTPUT_PATH = "data/cve_grounding.json"


def update_cve_grounding(output_path: str = DEFAULT_OUTPUT_PATH, dry_run: bool = False, limit: int = 500) -> None:
    print(f"=== NeuroShell IRE: Manual CVE Grounding Updater ===")
    print(f"Fetching CISA Known Exploited Vulnerabilities catalog from:\n  {CISA_KEV_URL}\n")

    try:
        resp = httpx.get(CISA_KEV_URL, timeout=30.0)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"ERROR: Failed to fetch CISA KEV feed: {e}", file=sys.stderr)
        sys.exit(1)

    vulnerabilities = data.get("vulnerabilities", [])
    print(f"Retrieved {len(vulnerabilities)} vulnerability entries from CISA KEV.")

    target_file = Path(output_path)

    grounding_data = {
        "_meta": {
            "description": "Offline local CVE grounding dataset for NeuroShell IRE",
            "updated_at": data.get("dateReleased", "2026-08-16"),
            "count": min(len(vulnerabilities), limit),
            "source": "CISA Known Exploited Vulnerabilities Catalog",
        }
    }

    added_count = 0
    for item in vulnerabilities[:limit]:
        cve_id = item.get("cveID")
        if not cve_id:
            continue

        cve_id = cve_id.strip().upper()
        short_desc = item.get("shortDescription", item.get("vulnerabilityName", ""))
        product = item.get("product", item.get("vendorProject", "Unknown Product"))

        grounding_data[cve_id] = {
            "description": short_desc,
            "affected_service": product,
            "severity": "CRITICAL" if "Remote Code Execution" in short_desc else "HIGH",
        }
        added_count += 1

    grounding_data["_meta"]["count"] = added_count
    print(f"Processed {added_count} CVE entries into grounding format.")

    if dry_run:
        print(f"\n[DRY RUN] Would write {added_count} CVE entries to {output_path}")
        print("Sample entry:")
        sample_key = next(k for k in grounding_data.keys() if not k.startswith("_"))
        print(f"  {sample_key}: {json.dumps(grounding_data[sample_key], indent=2)}")
        return

    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_text(json.dumps(grounding_data, indent=2), encoding="utf-8")
    print(f"\nSUCCESS: Updated CVE grounding dataset saved to {target_file.resolve()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manual CVE Grounding Dataset Updater")
    parser.add_argument("--output", default=DEFAULT_OUTPUT_PATH, help="Path to output cve_grounding.json")
    parser.add_argument("--dry-run", action="store_true", help="Fetch and process without saving")
    parser.add_argument("--limit", type=int, default=500, help="Maximum number of CVE entries to include")
    args = parser.parse_args()

    update_cve_grounding(output_path=args.output, dry_run=args.dry_run, limit=args.limit)
