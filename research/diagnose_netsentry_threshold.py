import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

# ---------------------------------------------------------
# 1. Load the same cleaned Wednesday dataset
# ---------------------------------------------------------
df = pd.read_csv("data/Wednesday_cleaned.csv")

# Match the preprocessing used in split_data.py
df = df[df["Label"] != "Heartbleed"].reset_index(drop=True)

print("=" * 70)
print("NETSENTRY DOS THRESHOLD DIAGNOSTIC")
print("=" * 70)

print(f"\nDataset shape: {df.shape}")
print(f"Label values: {df['Label'].value_counts().to_dict()}")


# ---------------------------------------------------------
# 2. Recreate the same binary labels and test split
# ---------------------------------------------------------
df["binary_label"] = np.where(df["Label"] == "BENIGN", 0, 1)

train_df, test_df = train_test_split(
    df,
    test_size=0.20,
    stratify=df["binary_label"],
    random_state=42,
)

test_df = test_df.reset_index(drop=True)

saved_y_test = np.load("data/y_test.npy")

assert np.array_equal(
    test_df["binary_label"].to_numpy(),
    saved_y_test,
), "ERROR: Recreated test split does not match saved y_test.npy"

print("\nTest split successfully matches data/y_test.npy")
print(f"Test rows: {len(test_df):,}")
print(
    f"Benign rows: {(test_df['binary_label'] == 0).sum():,}"
)
print(
    f"Attack rows: {(test_df['binary_label'] == 1).sum():,}"
)


# ---------------------------------------------------------
# 3. Identify the packet-count columns
# ---------------------------------------------------------
required_columns = [
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Duration",
]

missing_columns = [
    column for column in required_columns if column not in test_df.columns
]

if missing_columns:
    raise KeyError(
        f"Missing required columns: {missing_columns}\n"
        f"Available columns include:\n{test_df.columns.tolist()}"
    )

print("\nColumns used:")
for column in required_columns:
    print(f"  - {column}")


# ---------------------------------------------------------
# 4. Reproduce the NetSentry flow-level approximation
# ---------------------------------------------------------
test_df["total_packets"] = (
    test_df["Total Fwd Packets"]
    + test_df["Total Backward Packets"]
)

test_df["duration_seconds"] = (
    test_df["Flow Duration"] / 1_000_000
)

# Avoid division by zero.
safe_duration = test_df["duration_seconds"].replace(0, np.nan)

# Logic:
# - For flows lasting 10 seconds or less, use the raw packet total.
# - For flows lasting more than 10 seconds, estimate packets in a
#   10-second window using the average flow packet rate.
test_df["packets_per_10s"] = np.where(
    test_df["duration_seconds"] <= 10,
    test_df["total_packets"],
    (test_df["total_packets"] / safe_duration) * 10,
)

test_df["packets_per_10s"] = (
    test_df["packets_per_10s"]
    .replace([np.inf, -np.inf], np.nan)
    .fillna(test_df["total_packets"])
)

DOS_THRESHOLD = 50

test_df["crosses_dos_threshold"] = (
    test_df["packets_per_10s"] >= DOS_THRESHOLD
)


# ---------------------------------------------------------
# 5. Print summary statistics for benign and attack rows
# ---------------------------------------------------------
def print_group_statistics(group_name, group_df):
    print("\n" + "-" * 70)
    print(group_name)
    print("-" * 70)

    print(f"Rows: {len(group_df):,}")

    for column in [
        "total_packets",
        "duration_seconds",
        "packets_per_10s",
    ]:
        values = group_df[column]

        print(f"\n{column}:")
        print(f"  Minimum: {values.min():,.6f}")
        print(f"  25th percentile: {values.quantile(0.25):,.6f}")
        print(f"  Median: {values.median():,.6f}")
        print(f"  75th percentile: {values.quantile(0.75):,.6f}")
        print(f"  90th percentile: {values.quantile(0.90):,.6f}")
        print(f"  95th percentile: {values.quantile(0.95):,.6f}")
        print(f"  99th percentile: {values.quantile(0.99):,.6f}")
        print(f"  99.9th percentile: {values.quantile(0.999):,.6f}")
        print(f"  Maximum: {values.max():,.6f}")

    threshold_count = group_df["crosses_dos_threshold"].sum()
    threshold_percentage = (
        threshold_count / len(group_df) * 100
        if len(group_df) > 0
        else 0
    )

    print(
        f"\nRows with packets_per_10s >= {DOS_THRESHOLD}: "
        f"{threshold_count:,} "
        f"({threshold_percentage:.6f}%)"
    )


benign_df = test_df[test_df["binary_label"] == 0]
attack_df = test_df[test_df["binary_label"] == 1]

print_group_statistics("BENIGN TEST FLOWS", benign_df)
print_group_statistics("ATTACK TEST FLOWS", attack_df)


# ---------------------------------------------------------
# 6. Check each original attack type separately
# ---------------------------------------------------------
print("\n" + "=" * 70)
print("RESULTS BY ORIGINAL LABEL")
print("=" * 70)

label_summary = (
    test_df.groupby("Label")
    .agg(
        rows=("Label", "size"),
        median_total_packets=("total_packets", "median"),
        max_total_packets=("total_packets", "max"),
        median_duration_seconds=("duration_seconds", "median"),
        max_duration_seconds=("duration_seconds", "max"),
        median_packets_per_10s=("packets_per_10s", "median"),
        max_packets_per_10s=("packets_per_10s", "max"),
        rows_crossing_50=("crosses_dos_threshold", "sum"),
    )
    .sort_values(
        by="max_packets_per_10s",
        ascending=False,
    )
)

label_summary["percentage_crossing_50"] = (
    label_summary["rows_crossing_50"]
    / label_summary["rows"]
    * 100
)

print(label_summary.to_string())


# ---------------------------------------------------------
# 7. Display the strongest attack flows
# ---------------------------------------------------------
print("\n" + "=" * 70)
print("TOP 20 ATTACK FLOWS BY PACKETS PER 10 SECONDS")
print("=" * 70)

top_attack_flows = (
    attack_df[
        [
            "Label",
            "Total Fwd Packets",
            "Total Backward Packets",
            "total_packets",
            "Flow Duration",
            "duration_seconds",
            "packets_per_10s",
        ]
    ]
    .sort_values(
        by="packets_per_10s",
        ascending=False,
    )
    .head(20)
)

print(top_attack_flows.to_string(index=False))


# ---------------------------------------------------------
# 8. Compare several possible thresholds
# ---------------------------------------------------------
print("\n" + "=" * 70)
print("THRESHOLD SENSITIVITY")
print("=" * 70)

for threshold in [5, 10, 20, 30, 40, 50, 75, 100]:
    benign_triggered = (
        benign_df["packets_per_10s"] >= threshold
    ).sum()

    attack_triggered = (
        attack_df["packets_per_10s"] >= threshold
    ).sum()

    benign_rate = benign_triggered / len(benign_df) * 100
    attack_rate = attack_triggered / len(attack_df) * 100

    print(
        f"Threshold >= {threshold:3}: "
        f"Benign triggered = {benign_triggered:6,} "
        f"({benign_rate:8.4f}%) | "
        f"Attack triggered = {attack_triggered:6,} "
        f"({attack_rate:8.4f}%)"
    )


# ---------------------------------------------------------
# 9. Save diagnostic summaries
# ---------------------------------------------------------
label_summary.to_csv(
    "netsentry_threshold_by_label.csv"
)

top_attack_flows.to_csv(
    "netsentry_top_attack_flows.csv",
    index=False,
)

print("\nSaved:")
print("  netsentry_threshold_by_label.csv")
print("  netsentry_top_attack_flows.csv")

print("\nDiagnostic completed successfully.")