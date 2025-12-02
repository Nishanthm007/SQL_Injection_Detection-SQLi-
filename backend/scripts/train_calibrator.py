# backend/scripts/train_calibrator.py
"""
Train a simple Platt-scaling calibrator (logistic regression) over the model's raw CNN scores.
Saves calibrator to model_training/calibrator.pkl

Usage:
    cd Major-Project(SQLi)/backend
    python backend/scripts/train_calibrator.py
"""

import sqlite3
import csv
import pickle
import pathlib
import numpy as np
from sklearn.linear_model import LogisticRegression

# Project-relative paths (safe defaults)
# FIX: ROOT should point to project root (Major-Project(SQLi))
ROOT = pathlib.Path(__file__).resolve().parents[2]   # backend/scripts -> backend -> project root
PROJECT_ROOT = ROOT   # <--- corrected (was ROOT.parent before which was too high)
DB_PATH = PROJECT_ROOT / "logs" / "events.db"
EXPORT_CSV = PROJECT_ROOT / "logs" / "exports_false_positives.csv"
CALIB_PATH = PROJECT_ROOT / "model_training" / "calibrator.pkl"

def load_from_csv(csv_path):
    rows = []
    if not csv_path.exists():
        return rows
    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            try:
                pcnn = float(r.get("cnn_score") or r.get("p_cnn") or 0.0)
                label = int(r.get("label", 0))
                rows.append((pcnn, label))
            except Exception:
                continue
    return rows

def load_from_db(db_path, limit=1000):
    rows = []
    if not db_path.exists():
        return rows
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    try:
        # Grab recent labelled rows (label 0 and 1) with cnn_score present
        cur.execute("""
            SELECT cnn_score, label FROM attack_logs
            WHERE cnn_score IS NOT NULL
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        for pcnn, label in cur.fetchall():
            try:
                rows.append((float(pcnn), int(label)))
            except Exception:
                continue
    except Exception:
        pass
    finally:
        conn.close()
    return rows

def build_dataset():
    data = []
    # 1) prefer exported false positives CSV examples (these are label=0)
    data.extend(load_from_csv(EXPORT_CSV))
    # 2) augment with DB rows (both benign and malicious) to give both classes
    db_rows = load_from_db(DB_PATH, limit=5000)
    if db_rows:
        data.extend(db_rows)
    # Convert to numpy arrays
    if not data:
        return np.zeros((0,1)), np.array([])
    X = np.array([[d[0]] for d in data], dtype=np.float32)
    y = np.array([d[1] for d in data], dtype=np.int32)
    return X, y

def train_and_save(X, y, out_path):
    if X.shape[0] < 10:
        print("ERROR: Not enough samples to train a calibrator (need >=10). Found:", X.shape[0])
        return False
    # Basic logistic regression Platt scaling
    clf = LogisticRegression(C=1.0, solver="lbfgs", max_iter=200)
    clf.fit(X, y)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("wb") as f:
        pickle.dump(clf, f)
    print(f"Calibrator trained on {X.shape[0]} samples (positives={int(y.sum())}, negatives={int((y==0).sum())}).")
    print("Saved calibrator to:", out_path)
    return True

def main():
    print("Project root:", PROJECT_ROOT)
    print("DB path:", DB_PATH)
    print("Exports CSV (false positives):", EXPORT_CSV)
    print("Output calibrator path:", CALIB_PATH)
    X, y = build_dataset()
    print("Dataset size:", X.shape[0])
    if X.shape[0] > 0:
        print("Sample X (first 10):", X[:10].ravel().tolist())
        print("Sample y (first 10):", y[:10].tolist())
    ok = train_and_save(X, y, CALIB_PATH)
    if not ok:
        print("Calibrator training failed. Collect more labeled examples (both classes).")
    else:
        print("Done.")

if __name__ == "__main__":
    main()
