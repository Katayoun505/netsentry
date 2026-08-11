import pandas as pd
import numpy as np
import joblib
from tensorflow import keras

print("=" * 70)
print("Loading Friday data")
print("=" * 70)

df = pd.read_csv('data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv')
df.columns = df.columns.str.strip()
print("Raw shape:", df.shape)

numeric_cols = df.select_dtypes(include=[np.number]).columns

mask_bad = df[numeric_cols].isin([np.inf, -np.inf]).any(axis=1) | df[numeric_cols].isna().any(axis=1)
print("\nRows with Inf/NaN, by label (these get DROPPED):")
print(df.loc[mask_bad, 'Label'].value_counts())
print("\nRows WITHOUT Inf/NaN, by label (these get KEPT):")
print(df.loc[~mask_bad, 'Label'].value_counts())

df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
df = df.dropna().reset_index(drop=True)
print("\nShape after dropna:", df.shape)

with open('data/feature_columns.txt') as f:
    train_feature_cols = f.read().strip().split('\n')

y_true = (df['Label'] != 'BENIGN').astype(int).values
X_friday_raw = df[train_feature_cols].copy()

print("\n" + "=" * 70)
print("Scaling")
print("=" * 70)

scaler = joblib.load('scaler.pkl')
X_friday_scaled = scaler.transform(X_friday_raw)
print("Friday scaled mean:", np.mean(X_friday_scaled))
print("Friday scaled std:", np.std(X_friday_scaled))
print("Friday scaled min:", np.min(X_friday_scaled))
print("Friday scaled max:", np.max(X_friday_scaled))

print("\n" + "=" * 70)
print("CNN probability distribution")
print("=" * 70)

cnn_model = keras.models.load_model('cnn_model.keras')
X_friday_cnn_input = X_friday_scaled.reshape(X_friday_scaled.shape[0], X_friday_scaled.shape[1], 1)
cnn_probs = cnn_model.predict(X_friday_cnn_input, verbose=0).flatten()
print(pd.Series(cnn_probs).describe())
print("\nHistogram (10 bins):")
print(pd.cut(cnn_probs, bins=10).value_counts().sort_index())

print("\n" + "=" * 70)
print("RF probability distribution")
print("=" * 70)

rf_model = joblib.load('rf_model.pkl')
rf_probs = rf_model.predict_proba(X_friday_scaled)[:, 1]
print(pd.Series(rf_probs).describe())
print("\nHistogram (10 bins):")
print(pd.cut(rf_probs, bins=10).value_counts().sort_index())
print("\n" + "=" * 70)
print("Which features have extreme scaled values?")
print("=" * 70)

scaled_df = pd.DataFrame(X_friday_scaled, columns=train_feature_cols)
max_per_feature = scaled_df.abs().max().sort_values(ascending=False)
print(max_per_feature.head(10))