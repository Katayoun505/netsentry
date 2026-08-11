import pandas as pd
import numpy as np
import joblib
from tensorflow import keras
from sklearn.metrics import confusion_matrix, classification_report, roc_auc_score

# =====================================================================
# PHASE 2: Generalization test on Friday's port-scan traffic
#
# The CNN and RF were trained ONLY on Wednesday's DoS traffic. This
# script tests how well they generalize to a completely different
# attack type (port scanning) they have never seen.
#
# NOTE on NetSentry PORT_SCAN rule: NetSentry's real rule counts
# distinct destination ports contacted by one source IP. A single
# flow row has exactly one Destination Port value, so there is no
# way to reconstruct "distinct ports per source" from this dataset
# (same root limitation as the DOS_ATTEMPT rule on Wednesday's data:
# public CICIDS2017 CSVs discard Source IP entirely). We therefore
# do NOT approximate PORT_SCAN here, to avoid testing a different,
# invented rule and mislabeling it as NetSentry's actual logic. We
# DO test SUSPICIOUS_PORT, since it is a single-flow field check
# and can be reproduced exactly, with no approximation needed.
# =====================================================================

print("=" * 70)
print("STEP 1: Load and clean Friday port-scan data")
print("=" * 70)

df = pd.read_csv('data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv')
df.columns = df.columns.str.strip()  # remove leading/trailing spaces seen in raw headers
print("Raw shape:", df.shape)

# --- Clean infinities/NaN, matching how Wednesday's data was cleaned ---
# Flow Bytes/s and Flow Packets/s can be +/- inf when Flow Duration is 0.
numeric_cols = df.select_dtypes(include=[np.number]).columns
df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
rows_before = len(df)
df = df.dropna().reset_index(drop=True)
rows_after = len(df)
print(f"Dropped {rows_before - rows_after} rows with inf/NaN "
      f"({rows_before} -> {rows_after})")

# Keep a raw (unscaled) copy for the NetSentry rule check before we
# drop/scale anything, so Destination Port values stay in original units
df_raw = df.copy()

# --- Load the exact same zero-variance columns dropped from Wednesday ---
# We must apply the IDENTICAL feature set the CNN/RF were trained on.
with open('data/feature_columns.txt') as f:
    train_feature_cols = f.read().strip().split('\n')

print(f"\nCNN/RF were trained on {len(train_feature_cols)} features.")

# Encode labels: BENIGN = 0, PortScan (or anything else) = 1
y_true = (df['Label'] != 'BENIGN').astype(int).values
print("Label distribution:")
print(df['Label'].value_counts())

# Align Friday's columns to the exact training feature set/order
missing_cols = set(train_feature_cols) - set(df.columns)
extra_cols = set(df.columns) - set(train_feature_cols) - {'Label'}
if missing_cols:
    print("\nWARNING: Friday data is missing expected columns:", missing_cols)
if extra_cols:
    print("\nNote: Friday data has extra columns not used in training (ignored):", extra_cols)

X_friday_raw = df[train_feature_cols].copy()

print("\n" + "=" * 70)
print("STEP 2: Scale using the SAME fitted scaler from Wednesday training")
print("=" * 70)

scaler = joblib.load('scaler.pkl')
X_friday_scaled = scaler.transform(X_friday_raw)
print("Scaled. Mean:", np.mean(X_friday_scaled), "Std:", np.std(X_friday_scaled))
print("(Mean/std won't be exactly 0/1 here - that's expected, since this")
print(" scaler was fit on Wednesday's DoS data, not Friday's port-scan data.")
print(" This is the correct behavior for a true generalization test.)")

print("\n" + "=" * 70)
print("STEP 3: CNN predictions on Friday data")
print("=" * 70)

cnn_model = keras.models.load_model('cnn_model.keras')
# Reshape for Conv1D input the same way evaluate_model.py did
X_friday_cnn_input = X_friday_scaled.reshape(X_friday_scaled.shape[0], X_friday_scaled.shape[1], 1)

cnn_probs = cnn_model.predict(X_friday_cnn_input, verbose=0).flatten()
cnn_preds = (cnn_probs >= 0.5).astype(int)

cnn_cm = confusion_matrix(y_true, cnn_preds)
print("\nCNN Confusion Matrix:")
print(cnn_cm)
print("\nCNN Classification Report:")
print(classification_report(y_true, cnn_preds, target_names=['BENIGN', 'ATTACK'], digits=4))
try:
    cnn_auc = roc_auc_score(y_true, cnn_probs)
    print("CNN ROC-AUC:", cnn_auc)
except ValueError as e:
    cnn_auc = None
    print("ROC-AUC could not be computed:", e)

print("\n" + "=" * 70)
print("STEP 4: Random Forest predictions on Friday data")
print("=" * 70)

rf_model = joblib.load('rf_model.pkl')
rf_preds = rf_model.predict(X_friday_scaled)
rf_probs = rf_model.predict_proba(X_friday_scaled)[:, 1]

rf_cm = confusion_matrix(y_true, rf_preds)
print("\nRF Confusion Matrix:")
print(rf_cm)
print("\nRF Classification Report:")
print(classification_report(y_true, rf_preds, target_names=['BENIGN', 'ATTACK'], digits=4))
try:
    rf_auc = roc_auc_score(y_true, rf_probs)
    print("RF ROC-AUC:", rf_auc)
except ValueError as e:
    rf_auc = None
    print("ROC-AUC could not be computed:", e)

print("\n" + "=" * 70)
print("STEP 5: NetSentry SUSPICIOUS_PORT rule on Friday data (exact, not approximated)")
print("=" * 70)

SUSPICIOUS_PORTS = {4444, 31337, 12345, 6667, 1337}

def suspicious_port_predict(row):
    return 1 if row['Destination Port'] in SUSPICIOUS_PORTS else 0

ns_preds = df_raw.apply(suspicious_port_predict, axis=1).values
ns_cm = confusion_matrix(y_true, ns_preds)
print("\nNetSentry (SUSPICIOUS_PORT only) Confusion Matrix:")
print(ns_cm)
print("\nNetSentry (SUSPICIOUS_PORT only) Classification Report:")
print(classification_report(y_true, ns_preds, target_names=['BENIGN', 'ATTACK'], digits=4))
print("\nNote: PORT_SCAN rule not evaluated - requires per-source distinct-port")
print("counting that cannot be reconstructed from this dataset (no Source IP).")
print("This is documented as a dataset limitation in the paper.")

print("\n" + "=" * 70)
print("STEP 6: Save summary results")
print("=" * 70)

def safe_metrics(cm):
    tn, fp, fn, tp = cm.ravel()
    accuracy = (tp + tn) / (tp + tn + fp + fn)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    return accuracy, precision, recall, tp, fp, fn, tn

results = []
for name, cm, auc in [
    ('CNN (trained on DoS, tested on PortScan)', cnn_cm, cnn_auc),
    ('Random Forest (trained on DoS, tested on PortScan)', rf_cm, rf_auc),
    ('NetSentry SUSPICIOUS_PORT only (PORT_SCAN not evaluable)', ns_cm, None),
]:
    acc, prec, rec, tp, fp, fn, tn = safe_metrics(cm)
    results.append({
        'model': name, 'accuracy': acc, 'precision': prec, 'recall': rec,
        'roc_auc': auc, 'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn
    })

summary = pd.DataFrame(results)
summary.to_csv('friday_generalization_results.csv', index=False)
print(summary.to_string(index=False))
print("\nSaved to friday_generalization_results.csv")