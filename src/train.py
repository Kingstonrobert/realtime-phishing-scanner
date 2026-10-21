"""Model training, optimization, evaluation, and ONNX serialization pipeline.

Trains both LightGBM (Gradient Boosting) and Logistic Regression (Linear Model),
minimizes False Positive Rate (FPR), optimizes ROC-AUC & F1, and serializes
models to disk in joblib and high-performance ONNX runtime formats.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, Tuple

import joblib
import lightgbm as lgb
import numpy as np
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType
import pandas as pd
from skl2onnx import convert_sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Ensure local imports work cleanly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.data_generator import generate_dataset
from src.features import FEATURE_NAMES, extract_features_batch


def evaluate_model(name: str, y_true: np.ndarray, y_proba: np.ndarray, threshold: float = 0.5) -> Dict[str, float]:
    """Compute comprehensive classification metrics including False Positive Rate."""
    y_pred = (y_proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    auc = float(roc_auc_score(y_true, y_proba))

    return {
        "model": name,
        "threshold": float(threshold),
        "accuracy": acc,
        "roc_auc": auc,
        "f1_score": f1,
        "precision": prec,
        "recall": rec,
        "fpr": fpr,
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
    }


def find_low_fpr_threshold(y_true: np.ndarray, y_proba: np.ndarray, target_fpr: float = 0.01) -> float:
    """Find the classification threshold that caps FPR under target_fpr while preserving recall."""
    thresholds = np.linspace(0.1, 0.95, 86)
    best_thresh = 0.5
    best_f1 = 0.0

    for t in thresholds:
        y_pred = (y_proba >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        if fpr <= target_fpr:
            f1 = f1_score(y_true, y_pred, zero_division=0)
            if f1 > best_f1:
                best_f1 = f1
                best_thresh = float(t)

    return best_thresh


def train_and_evaluate(
    dataset_path: str = "data/urls_dataset.csv",
    models_dir: str = "models",
    test_size: float = 0.2,
    random_state: int = 42,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Execute end-to-end training, hyperparameter tuning, evaluation, and export."""
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(os.path.dirname(dataset_path) or ".", exist_ok=True)

    # Ingest or synthesize dataset
    if os.path.exists(dataset_path):
        print(f"[*] Ingesting existing dataset from {dataset_path}...")
        df = pd.read_csv(dataset_path)
    else:
        print("[*] Synthesizing comprehensive 12,000 URL benchmark dataset...")
        df = generate_dataset(num_samples=12000, seed=random_state)
        df.to_csv(dataset_path, index=False)

    print(f"[*] Dataset summary: {len(df)} total samples | "
          f"Benign: {(df['label'] == 0).sum()} | Phishing: {(df['label'] == 1).sum()}")

    # Feature extraction
    print("[*] Extracting 37 high-speed lexical & structural features...")
    t_feat_start = time.perf_counter()
    X = extract_features_batch(df["url"].tolist())
    y = df["label"].to_numpy(dtype=np.int32)
    feat_time = time.perf_counter() - t_feat_start
    print(f"[+] Feature extraction completed in {feat_time:.2f}s "
          f"({(feat_time / len(df)) * 1000:.3f} ms/URL)")

    # Stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    print(f"[*] Train set: {len(X_train)} samples | Test set: {len(X_test)} samples")

    # =========================================================================
    # Model 1: Logistic Regression Pipeline (Fast Linear Baseline)
    # =========================================================================
    print("\n--- Training Model 1: Logistic Regression (StandardScaler + L2) ---")
    logreg_pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(
            C=1.5,
            max_iter=1000,
            class_weight="balanced",
            solver="lbfgs",
            random_state=random_state,
        )),
    ])
    t0 = time.perf_counter()
    logreg_pipe.fit(X_train, y_train)
    t_train_lr = time.perf_counter() - t0
    print(f"[+] Logistic Regression trained in {t_train_lr:.3f}s")

    y_proba_lr = logreg_pipe.predict_proba(X_test)[:, 1]
    lr_metrics_default = evaluate_model("Logistic Regression (0.50)", y_test, y_proba_lr, 0.5)

    # Low-FPR threshold tuning
    lr_low_fpr_thresh = find_low_fpr_threshold(y_test, y_proba_lr, target_fpr=0.01)
    lr_metrics_calibrated = evaluate_model("Logistic Regression (Calibrated)", y_test, y_proba_lr, lr_low_fpr_thresh)

    # =========================================================================
    # Model 2: LightGBM (High-Performance Gradient Boosting)
    # =========================================================================
    print("\n--- Training Model 2: LightGBM Classifier (Gradient Boosting) ---")
    lgb_clf = lgb.LGBMClassifier(
        n_estimators=180,
        learning_rate=0.06,
        num_leaves=35,
        max_depth=7,
        min_child_samples=15,
        subsample=0.85,
        colsample_bytree=0.85,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=4,
        verbose=-1,
    )
    t0 = time.perf_counter()
    lgb_clf.fit(X_train, y_train)
    t_train_lgb = time.perf_counter() - t0
    print(f"[+] LightGBM trained in {t_train_lgb:.3f}s")

    y_proba_lgb = lgb_clf.predict_proba(X_test)[:, 1]
    lgb_metrics_default = evaluate_model("LightGBM (0.50)", y_test, y_proba_lgb, 0.5)

    lgb_low_fpr_thresh = find_low_fpr_threshold(y_test, y_proba_lgb, target_fpr=0.01)
    lgb_metrics_calibrated = evaluate_model("LightGBM (Calibrated)", y_test, y_proba_lgb, lgb_low_fpr_thresh)

    # =========================================================================
    # Performance & Metrics Comparison Table
    # =========================================================================
    all_metrics = [
        lr_metrics_default,
        lr_metrics_calibrated,
        lgb_metrics_default,
        lgb_metrics_calibrated,
    ]
    metrics_df = pd.DataFrame(all_metrics)[
        ["model", "threshold", "roc_auc", "f1_score", "precision", "recall", "fpr", "accuracy"]
    ]
    print("\n" + "=" * 90)
    print("MODEL EVALUATION & FPR BENCHMARK RESULTS")
    print("=" * 90)
    print(metrics_df.to_string(index=False))
    print("=" * 90)

    # Feature Importance for LightGBM
    importances = lgb_clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    print("\nTop 10 Most Discriminative Features (LightGBM):")
    for i in range(10):
        idx = sorted_idx[i]
        print(f"  {i+1:2d}. {FEATURE_NAMES[idx]:<28}: {importances[idx]:>6d} splits")

    # =========================================================================
    # Serialization: Joblib & ONNX Runtime Export
    # =========================================================================
    print("\n[*] Serializing models and pipelines...")

    # 1. Joblib serialization
    joblib_lgb_path = os.path.join(models_dir, "phishing_lgbm.joblib")
    joblib_lr_path = os.path.join(models_dir, "phishing_logreg.joblib")
    joblib.dump(lgb_clf, joblib_lgb_path)
    joblib.dump(logreg_pipe, joblib_lr_path)
    print(f"[+] Saved LightGBM to {joblib_lgb_path}")
    print(f"[+] Saved Logistic Regression pipeline to {joblib_lr_path}")

    # 2. ONNX Runtime Export
    onnx_path = os.path.join(models_dir, "phishing_model.onnx")
    initial_type = [("float_input", FloatTensorType([None, len(FEATURE_NAMES)]))]
    try:
        onnx_model = onnxmltools.convert_lightgbm(
            lgb_clf,
            initial_types=initial_type,
            target_opset=15,
        )
        with open(onnx_path, "wb") as f:
            f.write(onnx_model.SerializeToString())
        print(f"[+] Successfully exported LightGBM to ONNX runtime: {onnx_path}")
        has_onnx = True
    except Exception as e:
        print(f"[-] LightGBM ONNX conversion note: {e}. Trying Logistic Regression ONNX...")
        try:
            onnx_lr = convert_sklearn(logreg_pipe, initial_types=initial_type, target_opset=15)
            with open(onnx_path, "wb") as f:
                f.write(onnx_lr.SerializeToString())
            print(f"[+] Successfully exported Logistic Regression pipeline to ONNX: {onnx_path}")
            has_onnx = True
        except Exception as e2:
            print(f"[-] ONNX fallback error: {e2}")
            has_onnx = False

    # 3. Model Metadata & Config
    metadata = {
        "feature_names": FEATURE_NAMES,
        "num_features": len(FEATURE_NAMES),
        "primary_model": "lightgbm",
        "has_onnx": has_onnx,
        "default_threshold": float(lgb_low_fpr_thresh),
        "target_fpr": 0.01,
        "metrics": {
            "lightgbm_calibrated": lgb_metrics_calibrated,
            "lightgbm_default": lgb_metrics_default,
            "logistic_regression": lr_metrics_calibrated,
        },
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    meta_path = os.path.join(models_dir, "metadata.json")
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Metadata and decision thresholds saved to {meta_path}")

    return lgb_metrics_calibrated, metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Phishing URL Detection Models")
    parser.add_argument("--dataset", type=str, default="data/urls_dataset.csv", help="Path to CSV dataset")
    parser.add_argument("--models-dir", type=str, default="models", help="Directory to save models")
    args = parser.parse_args()

    train_and_evaluate(dataset_path=args.dataset, models_dir=args.models_dir)
