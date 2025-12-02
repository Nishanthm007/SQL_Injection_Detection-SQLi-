#!/usr/bin/env python3
"""
Evaluate CNN-only, Rules-only, and Hybrid detector on test_dataset.csv.

Usage:
    cd Major-Project(SQLi)/backend
    conda activate tfenv
    python scripts/evaluate_model.py

Outputs:
 - prints metrics to stdout
 - writes scripts/evaluation_results.csv with per-query results
"""
import csv
import pathlib
import sys
import math
from collections import Counter

# Ensure local imports resolve (run from backend/)
p = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(p))

# Local app imports (singletons already in your codebase)
from app.services.preprocessor import get_preprocessor
from app.utils.model_loader import get_model_loader
from app.services.detector import get_detector, HybridDetector

# Paths
TEST_CSV = pathlib.Path(__file__).resolve().parents[1] / "test_dataset.csv"
OUT_CSV = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "evaluation_results.csv"

# thresholds (you can tweak)
CNN_THRESHOLD = 0.5
RULE_THRESHOLD = 0.5

def load_test_csv(path):
    rows = []
    if not path.exists():
        raise SystemExit(f"Test CSV not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            q = r.get("query") or r.get("text") or ""
            lab = r.get("label")
            try:
                lab = int(lab)
            except Exception:
                lab = 0
            rows.append((q, lab))
    return rows

def safe_get(res, key, default=0.0):
    v = res.get(key, res.get(key.lower(), default))
    try:
        return float(v)
    except Exception:
        return default

def compute_metrics(y_true, y_pred):
    TP = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    TN = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    FP = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    FN = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
    total = len(y_true)
    accuracy = (TP + TN) / total if total else 0.0
    precision = TP / (TP + FP) if (TP + FP) else 0.0
    recall = TP / (TP + FN) if (TP + FN) else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
    return {
        "TP": TP, "TN": TN, "FP": FP, "FN": FN,
        "accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1
    }

def pretty_print_metrics(title, m):
    print(f"\n=== {title} ===")
    print(f"Total: {m['TP']+m['TN']+m['FP']+m['FN']}")
    print(f"TP: {m['TP']}  FP: {m['FP']}  TN: {m['TN']}  FN: {m['FN']}")
    print(f"Accuracy: {m['accuracy']:.4f}")
    print(f"Precision: {m['precision']:.4f}")
    print(f"Recall: {m['recall']:.4f}")
    print(f"F1: {m['f1']:.4f}")

def main():
    print("Loading test dataset:", TEST_CSV)
    data = load_test_csv(TEST_CSV)
    print("Loaded", len(data), "rows")

    # singletons (model + preprocessor + detector)
    print("Initializing detector & model (singleton loader)...")
    det = get_detector()  # HybridDetector singleton, will load preprocessor+model once

    results = []
    y_true = []
    cnn_preds = []
    rule_preds = []
    hybrid_preds = []

    # Iterate and collect predictions
    for idx, (query, label) in enumerate(data, start=1):
        try:
            res = det.analyze(query)
        except Exception as e:
            print(f"ERROR analyzing row {idx}: {e}")
            # fallback: mark benign
            res = {
                "cnn_prob": 0.0,
                "rule_score": 0.0,
                "final_label": 0,
                "p_cnn": 0.0,
                "p_rule": 0.0,
                "fused": 0.0,
                "details": {"raw_model_output": None}
            }

        # Robust extraction of numbers
        cnn_prob = safe_get(res, "cnn_prob", 0.0)
        rule_score = safe_get(res, "rule_score", 0.0)
        fused_score = safe_get(res, "fused_score", res.get("fused", 0.0))
        final_label = res.get("final_label", res.get("label", 0))
        try:
            final_label = int(final_label)
        except Exception:
            # if it's string like 'malicious' map accordingly
            final_label = 1 if str(final_label).lower().startswith("mal") else 0

        # decisions by thresholds
        cnn_label = 1 if cnn_prob >= CNN_THRESHOLD else 0
        rule_label = 1 if rule_score >= RULE_THRESHOLD else 0

        # append
        y_true.append(label)
        cnn_preds.append(cnn_label)
        rule_preds.append(rule_label)
        hybrid_preds.append(final_label)

        # store row result
        results.append({
            "idx": idx,
            "query": query,
            "label": label,
            "cnn_prob": round(cnn_prob, 6),
            "cnn_label": cnn_label,
            "rule_score": round(rule_score, 6),
            "rule_label": rule_label,
            "fused_score": round(fused_score, 6),
            "hybrid_label": final_label
        })

        # progress logging every 500 rows
        if idx % 500 == 0:
            print(f"Processed {idx}/{len(data)} rows")

    # compute metrics
    m_cnn = compute_metrics(y_true, cnn_preds)
    m_rule = compute_metrics(y_true, rule_preds)
    m_hybrid = compute_metrics(y_true, hybrid_preds)

    pretty_print_metrics("CNN-only (threshold 0.5)", m_cnn)
    pretty_print_metrics("Rule-only (threshold 0.5)", m_rule)
    pretty_print_metrics("Hybrid (detector.final_label)", m_hybrid)

    # Save per-query results
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "idx", "label", "cnn_prob", "cnn_label", "rule_score", "rule_label", "fused_score", "hybrid_label", "query"
        ])
        writer.writeheader()
        for r in results:
            # Truncate very long queries for CSV safety? we keep full query
            writer.writerow({
                "idx": r["idx"],
                "label": r["label"],
                "cnn_prob": r["cnn_prob"],
                "cnn_label": r["cnn_label"],
                "rule_score": r["rule_score"],
                "rule_label": r["rule_label"],
                "fused_score": r["fused_score"],
                "hybrid_label": r["hybrid_label"],
                "query": r["query"]
            })

    print("\nSaved detailed results to:", OUT_CSV)
    print("Done.")

if __name__ == "__main__":
    main()
