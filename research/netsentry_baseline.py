import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, classification_report, roc_auc_score

# --- Load the RAW (unscaled) test data with original column names ---
# We need actual Destination Port / Flow Duration / packet count values,
# not the standardized (mean=0, std=1) versions used for the CNN/RF,
# since NetSentry's real thresholds are in raw units (e.g. "50 packets", "port 4444")
df = pd.read_csv('data/Wednesday_cleaned.csv')
df = df[df['Label'] != 'Heartbleed'].reset_index(drop=True)

# Drop the same zero-variance columns we dropped before, for consistency
zero_var_cols = df.drop(columns=['Label']).columns[df.drop(columns=['Label']).nunique() == 1].tolist()
df = df.drop(columns=zero_var_cols)

y_true = (df['Label'] != 'BENIGN').astype(int).values

# --- We must use the SAME test split as the CNN/RF for a fair comparison ---
# Re-run the identical train_test_split with the same random_state to recover
# which rows ended up in the test set
from sklearn.model_selection import train_test_split
X_full = df.drop(columns=['Label'])
_, X_test_raw, _, y_test_check = train_test_split(
    X_full, y_true, test_size=0.2, random_state=42, stratify=y_true
)

# Sanity check: y_test_check should exactly match the saved y_test.npy
y_test_saved = np.load('data/y_test.npy')
assert np.array_equal(y_test_check, y_test_saved), "Test set mismatch! Split doesn't match CNN/RF."
print("Confirmed: using the identical test set as CNN/RF for fair comparison.\n")

# --- NetSentry's actual thresholds (from detection.py) ---
DOS_PACKET_COUNT_THRESHOLD = 50
DOS_WINDOW_SECONDS = 10
SUSPICIOUS_PORTS = {4444, 31337, 12345, 6667, 1337}

def netsentry_predict(row):
    """
    Approximates NetSentry's rule-based detection at the flow level.

    DOS_ATTEMPT (approximated): NetSentry's real rule counts packets per
    source IP within a rolling 10-second window and fires if count >= 50.
    Since we only have single-flow statistics (no source IP grouping
    across multiple flows), we approximate as follows:
      - If the flow lasted 10 seconds or less, a single 10-second window
        can contain at most all of this flow's packets, so we use the
        raw total_packets directly (no extrapolation, since we cannot
        count packets that were never actually sent).
      - If the flow lasted longer than 10 seconds, we estimate the
        densest possible 10-second slice using the flow's average rate.
    This corrects an earlier version that projected short, bursty flows'
    rates out to a full 10-second window, which fabricated packet counts
    that were never sent and caused massive false positives on benign
    traffic (most benign flows are short and complete in well under a
    second).

    SUSPICIOUS_PORT: applied exactly as NetSentry does, checking the flow's
    destination port against the same known-malicious port set.
    """
    total_packets = row['Total Fwd Packets'] + row['Total Backward Packets']
    duration_seconds = row['Flow Duration'] / 1_000_000  # microseconds -> seconds

    if duration_seconds <= DOS_WINDOW_SECONDS:
        # A window this short cannot contain more packets than the flow
        # actually sent - no extrapolation.
        packets_per_10s = total_packets
    else:
        packets_per_second = total_packets / duration_seconds
        packets_per_10s = packets_per_second * DOS_WINDOW_SECONDS

    # DOS_ATTEMPT rule (rate-based flow-level approximation)
    if packets_per_10s >= DOS_PACKET_COUNT_THRESHOLD:
        return 1

    # SUSPICIOUS_PORT rule (exact match to NetSentry logic)
    if row['Destination Port'] in SUSPICIOUS_PORTS:
        return 1

    return 0

print("Applying NetSentry rule logic to test set...")
y_pred = X_test_raw.apply(netsentry_predict, axis=1).values

# --- Same metrics as CNN/RF, for direct comparison ---
cm = confusion_matrix(y_test_saved, y_pred)
tn, fp, fn, tp = cm.ravel()

print("\nConfusion Matrix:")
print(cm)
print(f"\nTrue Negatives (correctly identified benign):  {tn}")
print(f"False Positives (benign flagged as attack):     {fp}")
print(f"False Negatives (attack missed, called benign): {fn}")
print(f"True Positives (correctly identified attack):   {tp}")

print("\nClassification Report:")
print(classification_report(y_test_saved, y_pred, target_names=['BENIGN', 'ATTACK'], digits=4))

# Note: NetSentry is a binary rule engine (no probability score), so ROC-AUC
# isn't directly applicable the same way it is for CNN/RF - we just report
# accuracy/precision/recall/F1 for a fair rule-based vs ML-based comparison

# Save results
accuracy = (tp + tn) / (tp + tn + fp + fn)
precision = tp / (tp + fp) if (tp + fp) > 0 else 0
recall = tp / (tp + fn) if (tp + fn) > 0 else 0

summary = pd.DataFrame([{
    'model': 'NetSentry (rule-based)',
    'accuracy': accuracy,
    'precision': precision,
    'recall': recall
}])
summary.to_csv('netsentry_results.csv', index=False)
print("\nSaved summary to netsentry_results.csv")