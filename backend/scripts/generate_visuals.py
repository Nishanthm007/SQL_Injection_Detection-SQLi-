#!/usr/bin/env python3
"""
Generate evaluation summary JSON/CSV and plots from evaluation_results.csv

Saves outputs to:
  backend/scripts/evaluation_outputs/
  (also copies to /mnt/data/evaluation_outputs/ if running in sandbox)

Run from backend/:
  conda activate tfenv
  cd Major-Project(SQLi)/backend
  python scripts/generate_visuals.py

Outputs:
  - evaluation_summary.json
  - evaluation_summary.csv
  - auc_summary.csv
  - metrics_bar.png
  - roc_curves.png
  - confusion_matrices.png
  (All under backend/scripts/evaluation_outputs/)
"""
import os, csv, json, pathlib
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, auc, confusion_matrix

# Paths
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
EVAL_CSV = PROJECT_ROOT / "scripts" / "evaluation_results.csv"
OUT_DIR = PROJECT_ROOT / "scripts" / "evaluation_outputs"
MNT_DIR = pathlib.Path("/mnt/data/evaluation_outputs")

OUT_DIR.mkdir(parents=True, exist_ok=True)
try:
    MNT_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    # Not a problem if /mnt/data isn't writable in your env
    pass

if not EVAL_CSV.exists():
    raise SystemExit(f"evaluation_results.csv not found at {EVAL_CSV}. Run evaluation first: scripts/evaluate_model.py")

# Load CSV
rows = []
with EVAL_CSV.open("r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for r in reader:
        # parse numeric fields safely
        r["label"] = int(r.get("label", 0) or 0)
        r["cnn_prob"] = float(r.get("cnn_prob", 0.0) or 0.0)
        r["cnn_label"] = int(r.get("cnn_label", 0) or 0)
        r["rule_score"] = float(r.get("rule_score", 0.0) or 0.0)
        r["rule_label"] = int(r.get("rule_label", 0) or 0)
        r["fused_score"] = float(r.get("fused_score", 0.0) or 0.0)
        r["hybrid_label"] = int(r.get("hybrid_label", 0) or 0)
        rows.append(r)

y_true = np.array([r["label"] for r in rows])
cnn_prob = np.array([r["cnn_prob"] for r in rows])
cnn_pred = np.array([r["cnn_label"] for r in rows])
rule_pred = np.array([r["rule_label"] for r in rows])
fused_score = np.array([r["fused_score"] for r in rows])
hybrid_pred = np.array([r["hybrid_label"] for r in rows])

def metrics_from_preds(y, pred):
    cm = confusion_matrix(y, pred)
    # Handle possible shapes
    if cm.shape == (2,2):
        tn, fp, fn, tp = cm.ravel()
    else:
        # fallback when one class missing
        tn = int(cm[0,0]) if cm.shape[0]>0 and cm.shape[1]>0 else 0
        fp = int(cm[0,1]) if cm.shape[0]>0 and cm.shape[1]>1 else 0
        fn = int(cm[1,0]) if cm.shape[0]>1 and cm.shape[1]>0 else 0
        tp = int(cm[1,1]) if cm.shape[0]>1 and cm.shape[1]>1 else 0
    total = tp+tn+fp+fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
    return {"TP": int(tp), "FP": int(fp), "TN": int(tn), "FN": int(fn),
            "accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1}

summary = {
    "CNN": metrics_from_preds(y_true, cnn_pred),
    "Rule": metrics_from_preds(y_true, rule_pred),
    "Hybrid": metrics_from_preds(y_true, hybrid_pred),
    "total_samples": int(len(rows))
}

# Save summary JSON and CSV
summary_json_path = OUT_DIR / "evaluation_summary.json"
summary_csv_path = OUT_DIR / "evaluation_summary.csv"
with summary_json_path.open("w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)
with summary_csv_path.open("w", encoding="utf-8", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["model","TP","FP","TN","FN","accuracy","precision","recall","f1"])
    for model in ["CNN","Rule","Hybrid"]:
        m = summary[model]
        writer.writerow([model, m["TP"], m["FP"], m["TN"], m["FN"], f"{m['accuracy']:.6f}", f"{m['precision']:.6f}", f"{m['recall']:.6f}", f"{m['f1']:.6f}"])

# Attempt to also save into /mnt/data for convenience (optional)
try:
    import shutil
    shutil.copy(str(summary_json_path), str(MNT_DIR / summary_json_path.name))
    shutil.copy(str(summary_csv_path), str(MNT_DIR / summary_csv_path.name))
except Exception:
    pass

# --------- Plot 1: metrics bar (grouped) ----------
metrics_list = ["accuracy","precision","recall","f1"]
models = ["CNN","Rule","Hybrid"]
x = np.arange(len(models))
width = 0.2

plt.figure(figsize=(9,5))
for i, met in enumerate(metrics_list):
    plt.bar(x + (i-1.5)*width + width/2, [summary[m][met] for m in models], width, label=met)
plt.xticks(x, models)
plt.ylabel("Score")
plt.title("Metrics by Model (Accuracy/Precision/Recall/F1)")
plt.legend()
metrics_bar_path = OUT_DIR / "metrics_bar.png"
plt.tight_layout()
plt.savefig(metrics_bar_path)
try:
    shutil.copy(str(metrics_bar_path), str(MNT_DIR / metrics_bar_path.name))
except Exception:
    pass
plt.close()

# --------- Plot 2: ROC curves ----------
plt.figure(figsize=(7,6))
fpr_c, tpr_c, _ = roc_curve(y_true, cnn_prob)
auc_c = auc(fpr_c, tpr_c)
plt.plot(fpr_c, tpr_c, label=f"CNN (AUC={auc_c:.3f})")
# Hybrid ROC from fused_score
fpr_h, tpr_h, _ = roc_curve(y_true, fused_score)
auc_h = auc(fpr_h, tpr_h)
plt.plot(fpr_h, tpr_h, label=f"Hybrid (AUC={auc_h:.3f})")
plt.plot([0,1],[0,1],"--", linewidth=1)
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curves")
plt.legend()
roc_path = OUT_DIR / "roc_curves.png"
plt.tight_layout()
plt.savefig(roc_path)
try:
    shutil.copy(str(roc_path), str(MNT_DIR / roc_path.name))
except Exception:
    pass
plt.close()

# --------- Plot 3: confusion matrices (3 side-by-side) ----------
cm_c = confusion_matrix(y_true, cnn_pred)
cm_r = confusion_matrix(y_true, rule_pred)
cm_h = confusion_matrix(y_true, hybrid_pred)

plt.figure(figsize=(12,4))
cms = [cm_c, cm_r, cm_h]
titles = ["CNN Confusion Matrix", "Rule Confusion Matrix", "Hybrid Confusion Matrix"]
for i, cm in enumerate(cms, start=1):
    ax = plt.subplot(1,3,i)
    ax.imshow(cm, interpolation='nearest')
    ax.set_title(titles[i-1])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_xticks([0,1]); ax.set_yticks([0,1])
    ax.set_xticklabels(["0","1"]); ax.set_yticklabels(["0","1"])
    for (j,k), val in __import__("numpy").ndenumerate(cm):
        ax.text(k, j, int(val), ha="center", va="center")
plt.tight_layout()
cm_path = OUT_DIR / "confusion_matrices.png"
plt.savefig(cm_path)
try:
    shutil.copy(str(cm_path), str(MNT_DIR / cm_path.name))
except Exception:
    pass
plt.close()

# Save AUC summary
auc_summary_path = OUT_DIR / "auc_summary.csv"
with auc_summary_path.open("w", encoding="utf-8", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["model","auc"])
    writer.writerow(["CNN", f"{auc_c:.6f}"])
    writer.writerow(["Hybrid", f"{auc_h:.6f}"])
try:
    shutil.copy(str(auc_summary_path), str(MNT_DIR / auc_summary_path.name))
except Exception:
    pass

print("Generated outputs in:", OUT_DIR.resolve())
print("If available, also copied to:", MNT_DIR.resolve())
print("Files produced:")
for p in OUT_DIR.iterdir():
    print(" -", p.name)
