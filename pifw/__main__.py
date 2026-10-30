"""CLI: python -m pifw "text"  |  python -m pifw --eval data/eval.jsonl"""
import argparse
import json
import sys

from .scanner import scan


def evaluate(path: str) -> dict:
    tp = fp = tn = fn = 0
    errors = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            row = json.loads(line)
            flagged = scan(row["text"], source=row.get("source", "user")).verdict != "allow"
            if row["label"] == "attack":
                tp += flagged
                fn += not flagged
            else:
                fp += flagged
                tn += not flagged
            if flagged != (row["label"] == "attack"):
                errors.append({"type": "FN" if not flagged else "FP", "text": row["text"][:80]})
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": round(precision, 3),
            "recall": round(recall, 3), "f1": round(f1, 3), "errors": errors}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pifw", description="Prompt-injection firewall")
    ap.add_argument("text", nargs="?", help="text to scan (default: stdin)")
    ap.add_argument("--source", default="user", choices=["user", "retrieved"])
    ap.add_argument("--eval", metavar="JSONL", help="run the labeled evaluation set")
    args = ap.parse_args(argv)
    if args.eval:
        print(json.dumps(evaluate(args.eval), indent=2))
        return 0
    text = args.text if args.text is not None else sys.stdin.read()
    res = scan(text, source=args.source)
    print(json.dumps({"verdict": res.verdict, "score": res.score,
                      "findings": [f.__dict__ for f in res.findings]}, indent=2))
    return 2 if res.blocked else 0


if __name__ == "__main__":
    sys.exit(main())
