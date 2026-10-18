import os
import json
import csv
import re
from collections import defaultdict

from src.schemas.models import IREIntentContract
from src.intent.intent_interpreter import IntentInterpreter
from src.intent.query_constructor import QueryConstructor
from src.rag.vector_retriever import VectorRetriever


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BENCHMARK_PATH = os.path.join(
    ROOT,
    "data",
    "benchmark_eval.json"
)

JSON_OUT = os.path.join(
    ROOT,
    "scratch",
    "rag_retrieval_final_metrics.json"
)

CSV_OUT = os.path.join(
    ROOT,
    "scratch",
    "rag_retrieval_final_audit.csv"
)

SUPPORTED_TOOLS = {"nmap", "nikto", "gobuster"}
TOP_K = 5


def load_cases():
    with open(BENCHMARK_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    selected = []

    for case in data:

        if case.get("excluded"):
            continue

        if not case.get("expect_success", False):
            continue

        provenance = case.get("provenance", {})

        if provenance.get("type") != "dataset_derived":
            continue

        contract = (
            case.get("body", {})
            .get("intent_contract", {})
        )

        tool = contract.get("tool_hint")

        if tool not in SUPPORTED_TOOLS:
            continue

        selected.append(case)

    return selected


def clean_flag(flag):
    return str(flag).strip().lower()


def relevance_terms(case):
    sem = case.get("expected_semantics", {})

    terms = set()

    for flag in sem.get("expected_flags", []):
        flag = clean_flag(flag)

        if flag:
            terms.add(flag)

    for mod in sem.get("modifiers", []):
        mod = str(mod).strip().lower()

        if not mod:
            continue

        for piece in re.split(r"[:=,\s]+", mod):
            if len(piece) >= 2:
                terms.add(piece)

    command = sem.get(
        "canonical_reference_command",
        ""
    ).lower()

    for term in [
        "dir",
        "vhost",
        "dns",
        "ssl",
        "evasion",
        "tuning",
        "ping",
        "udp",
        "aggressive",
        "version"
    ]:
        if term in command:
            terms.add(term)

    return sorted(terms)


def doc_matches(doc_text, terms):
    text = doc_text.lower()

    return [
        term
        for term in terms
        if term and term in text
    ]


def pct(value, total):
    if not total:
        return 0.0

    return round(
        (value / total) * 100,
        2
    )


def main():

    os.makedirs(
        os.path.join(ROOT, "scratch"),
        exist_ok=True
    )

    cases = load_cases()

    print(
        "Eligible retrieval benchmark cases:",
        len(cases)
    )

    interpreter = IntentInterpreter()
    query_constructor = QueryConstructor()
    retriever = VectorRetriever()

    hit1 = 0
    hit3 = 0
    hit5 = 0

    reciprocal_ranks = []
    top1_scores = []

    per_tool = defaultdict(
        lambda: {
            "count": 0,
            "hit1": 0,
            "hit3": 0,
            "hit5": 0,
            "rr_sum": 0.0,
            "top1_score_sum": 0.0
        }
    )

    audit_rows = []

    for case in cases:

        contract_dict = (
            case["body"]["intent_contract"]
        )

        contract = IREIntentContract.model_validate(
            contract_dict
        )

        params = interpreter.interpret(contract)

        query = query_constructor.build_query(
            params
        )

        tool = params.get("tool_hint")

        docs = retriever.retrieve(
            query,
            tool_hint=tool,
            top_k=TOP_K,
            score_threshold=0.0
        )

        terms = relevance_terms(case)

        first_relevant_rank = None

        if docs:
            top1_scores.append(
                docs[0]["score"]
            )

        for rank, doc in enumerate(
            docs,
            start=1
        ):

            matched_terms = doc_matches(
                doc["content"],
                terms
            )

            relevant = (
                len(matched_terms) > 0
            )

            if (
                relevant
                and first_relevant_rank is None
            ):
                first_relevant_rank = rank

            audit_rows.append({
                "case_id": case.get("id"),
                "case_name": case.get("name"),
                "tool": tool,
                "query": query,
                "expected_terms":
                    " | ".join(terms),
                "rank": rank,
                "score": doc["score"],
                "proxy_relevant": relevant,
                "matched_terms":
                    " | ".join(matched_terms),
                "content_excerpt":
                    doc["content"][:500]
                    .replace("\n", " ")
            })

        case_hit1 = (
            first_relevant_rank is not None
            and first_relevant_rank <= 1
        )

        case_hit3 = (
            first_relevant_rank is not None
            and first_relevant_rank <= 3
        )

        case_hit5 = (
            first_relevant_rank is not None
            and first_relevant_rank <= 5
        )

        rr = (
            1.0 / first_relevant_rank
            if first_relevant_rank
            else 0.0
        )

        hit1 += int(case_hit1)
        hit3 += int(case_hit3)
        hit5 += int(case_hit5)

        reciprocal_ranks.append(rr)

        d = per_tool[tool]

        d["count"] += 1
        d["hit1"] += int(case_hit1)
        d["hit3"] += int(case_hit3)
        d["hit5"] += int(case_hit5)
        d["rr_sum"] += rr

        if docs:
            d["top1_score_sum"] += (
                docs[0]["score"]
            )

        print(
            f"{case['id']} | "
            f"{tool:<8} | "
            f"first relevant rank="
            f"{first_relevant_rank} | "
            f"top1 score="
            f"{docs[0]['score'] if docs else 'NONE'}"
        )

    total = len(cases)

    metrics = {
        "benchmark_cases": total,
        "top_k": TOP_K,

        "proxy_hit_at_1_pct":
            pct(hit1, total),

        "proxy_hit_at_3_pct":
            pct(hit3, total),

        "proxy_hit_at_5_pct":
            pct(hit5, total),

        "proxy_mrr_at_5":
            round(
                sum(reciprocal_ranks) / total,
                4
            ) if total else 0.0,

        "mean_top1_similarity":
            round(
                sum(top1_scores)
                / len(top1_scores),
                4
            ) if top1_scores else 0.0,

        "per_tool": {}
    }

    for tool, d in sorted(
        per_tool.items()
    ):

        n = d["count"]

        metrics["per_tool"][tool] = {
            "count": n,

            "hit_at_1_pct":
                pct(d["hit1"], n),

            "hit_at_3_pct":
                pct(d["hit3"], n),

            "hit_at_5_pct":
                pct(d["hit5"], n),

            "mrr_at_5":
                round(
                    d["rr_sum"] / n,
                    4
                ) if n else 0.0,

            "mean_top1_similarity":
                round(
                    d["top1_score_sum"] / n,
                    4
                ) if n else 0.0
        }

    with open(
        JSON_OUT,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            metrics,
            f,
            indent=2,
            ensure_ascii=False
        )

    if audit_rows:

        with open(
            CSV_OUT,
            "w",
            newline="",
            encoding="utf-8-sig"
        ) as f:

            writer = csv.DictWriter(
                f,
                fieldnames=audit_rows[0].keys()
            )

            writer.writeheader()
            writer.writerows(audit_rows)

    print("\n================================")
    print(" FINAL C2 RAG RETRIEVAL RESULTS")
    print("================================")

    print("Cases:", total)

    print(
        "Proxy Hit@1:",
        metrics["proxy_hit_at_1_pct"],
        "%"
    )

    print(
        "Proxy Hit@3:",
        metrics["proxy_hit_at_3_pct"],
        "%"
    )

    print(
        "Proxy Hit@5:",
        metrics["proxy_hit_at_5_pct"],
        "%"
    )

    print(
        "Proxy MRR@5:",
        metrics["proxy_mrr_at_5"]
    )

    print(
        "Mean Top-1 similarity:",
        metrics["mean_top1_similarity"]
    )

    print("\nPER TOOL")

    for tool, data in (
        metrics["per_tool"].items()
    ):
        print(
            tool.upper(),
            data
        )

    print("\nSaved:")
    print(JSON_OUT)
    print(CSV_OUT)

    print(
        "\nNOTE: Relevance is an automated "
        "proxy based on expected flags and "
        "modifiers. It is not human-annotated "
        "relevance."
    )


if __name__ == "__main__":
    main()