import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split


DATA_PATH = "data/Wednesday_cleaned.csv"

FEATURES = [
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Subflow Fwd Bytes",
    "Subflow Bwd Bytes",
]


# Load and reproduce the original preprocessing.
df = pd.read_csv(DATA_PATH)
df = df[df["Label"] != "Heartbleed"].reset_index(drop=True)

y = (df["Label"] != "BENIGN").astype(int)

train_df, test_df = train_test_split(
    df,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

# Verify that the reconstructed test labels match the saved test set.
saved_y_test = np.load("data/y_test.npy")
recreated_y_test = (test_df["Label"] != "BENIGN").astype(int).to_numpy()

assert np.array_equal(
    recreated_y_test,
    saved_y_test,
), "Recreated test split does not match data/y_test.npy"

missing = [feature for feature in FEATURES if feature not in train_df.columns]

if missing:
    raise KeyError(f"Missing features: {missing}")

# Use training data only to avoid test-set leakage.
summary_rows = []

for feature in FEATURES:
    values = pd.to_numeric(train_df[feature], errors="coerce")
    values = values.replace([np.inf, -np.inf], np.nan).dropna()

    summary_rows.append(
        {
            "feature": feature,
            "minimum": values.min(),
            "p01": values.quantile(0.01),
            "p05": values.quantile(0.05),
            "median": values.quantile(0.50),
            "p95": values.quantile(0.95),
            "p99": values.quantile(0.99),
            "maximum": values.max(),
        }
    )

summary = pd.DataFrame(summary_rows)

print("\nTRAINING-DATA PADDING FEATURE RANGES\n")
print(summary.to_string(index=False))

summary.to_csv(
    "padding_feature_ranges.csv",
    index=False,
)

print("\nSaved: padding_feature_ranges.csv")