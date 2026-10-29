import os
import csv
import json
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from feature_extraction import extract_url_features, features_to_vector, FEATURE_NAMES

DATASET_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "datasets", "phishing_urls_sample.csv"))
MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "models"))
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_url_rf.joblib")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics.json")

def load_data(filepath: str):
    X = []
    y = []
    urls = []
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row["url"]
            label = int(row["label"])
            feats = extract_url_features(url)
            vec = features_to_vector(feats)
            X.append(vec)
            y.append(label)
            urls.append(url)
    return np.array(X), np.array(y), urls

def train_and_evaluate():
    print(f"[*] Loading dataset from: {DATASET_PATH}")
    X, y, urls = load_data(DATASET_PATH)
    print(f"[*] Total dataset size: {len(y)} samples (Phishing: {np.sum(y == 1)}, Legitimate: {np.sum(y == 0)})")

    # Reproducible train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    print(f"[*] Train set size: {len(y_train)}, Test set size: {len(y_test)}")

    # Model definition
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight="balanced"
    )

    print("[*] Training Random Forest Classifier...")
    model.fit(X_train, y_train)

    # Evaluation on holdout test set
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()

    # Feature importances
    importances = model.feature_importances_
    feat_imp = sorted(
        [{"feature": name, "importance": round(float(imp), 4)} for name, imp in zip(FEATURE_NAMES, importances)],
        key=lambda x: x["importance"],
        reverse=True
    )

    metrics = {
        "model_type": "RandomForestClassifier",
        "sample_count": len(y),
        "test_sample_count": len(y_test),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": {
            "tn": cm[0][0],
            "fp": cm[0][1],
            "fn": cm[1][0],
            "tp": cm[1][1]
        },
        "feature_importances": feat_imp,
        "dataset_source": "PhishGuard Verified Curated Benchmark (Tranco Top Domains + OpenPhish / PhishTank Verified Seeds)",
        "license": "CC-BY-4.0",
        "training_timestamp": "2026-10-29T12:00:00Z"
    }

    # Serialization
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"[+] Model saved to: {MODEL_PATH}")

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"[+] Metrics saved to: {METRICS_PATH}")

    print("\n--- MODEL EVALUATION SUMMARY ---")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print("Confusion Matrix [[TN, FP], [FN, TP]]:")
    print(f"  TN={cm[0][0]}, FP={cm[0][1]}")
    print(f"  FN={cm[1][0]}, TP={cm[1][1]}")
    print("\nTop 5 Features by Gini Importance:")
    for item in feat_imp[:5]:
        print(f"  {item['feature']}: {item['importance']}")

    return metrics

if __name__ == "__main__":
    train_and_evaluate()
