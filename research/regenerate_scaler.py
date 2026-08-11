import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib

# --- Reproduce split_data.py's pipeline EXACTLY, step for step ---

# Load cleaned data
df = pd.read_csv('data/Wednesday_cleaned.csv')

# Drop Heartbleed rows (only 11 samples - not enough to learn from)
df = df[df['Label'] != 'Heartbleed'].reset_index(drop=True)

# Split features (X) from label (y)
X = df.drop(columns=['Label'])
y = df['Label']

# Drop zero-variance columns
zero_var_cols = X.columns[X.nunique() == 1].tolist()
print("Dropping zero-variance columns:", zero_var_cols)
X = X.drop(columns=zero_var_cols)

print("X shape after dropping zero-variance columns:", X.shape)

# Encode labels as binary: BENIGN = 0, everything else (attack) = 1
y_binary = (y != 'BENIGN').astype(int)

# Train/test split (80/20), stratified to preserve class balance
X_train, X_test, y_train, y_test = train_test_split(
    X, y_binary,
    test_size=0.2,
    random_state=42,
    stratify=y_binary
)

# --- Re-fit the scaler on X_train, exactly as split_data.py did ---
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("\nScaled train mean (should be ~0):", np.mean(X_train_scaled))
print("Scaled train std (should be ~1):", np.std(X_train_scaled))

# --- Save the scaler this time, so we never lose it again ---
joblib.dump(scaler, 'scaler.pkl')
print("\nSaved fitted scaler to scaler.pkl")

# --- Verification: does this reproduce the EXACT arrays already on disk? ---
X_test_saved = np.load('data/X_test.npy')
y_test_saved = np.load('data/y_test.npy')

y_match = np.array_equal(y_test.values, y_test_saved)
X_match = np.allclose(X_test_scaled, X_test_saved, atol=1e-8)

print("\n--- Verification against existing saved arrays ---")
print("y_test matches saved y_test.npy:", y_match)
print("X_test_scaled matches saved X_test.npy:", X_match)

if y_match and X_match:
    print("\nSUCCESS: Regenerated scaler is verified identical to the original.")
    print("scaler.pkl can now be trusted to scale new data (e.g. Friday's CSV)")
    print("in a way consistent with how the CNN/RF were trained.")
else:
    print("\nWARNING: Mismatch detected! Do not proceed to Phase 2 with this scaler.")
    print("This means the pipeline above doesn't exactly match what split_data.py did.")
    if not X_match:
        max_diff = np.max(np.abs(X_test_scaled - X_test_saved))
        print(f"Max absolute difference in X_test: {max_diff}")