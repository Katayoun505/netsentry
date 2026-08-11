import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import numpy as np

# Load cleaned data
df = pd.read_csv('data/Wednesday_cleaned.csv')

# Drop Heartbleed rows (only 11 samples - not enough to learn from)
df = df[df['Label'] != 'Heartbleed'].reset_index(drop=True)

# Split features (X) from label (y)
X = df.drop(columns=['Label'])
y = df['Label']

# Drop zero-variance columns (columns where every value is identical -
# these carry no information and can cause division-by-zero in scaling)
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

print("\nTrain shape:", X_train.shape)
print("Test shape:", X_test.shape)

# Scale features - fit on train only, transform both
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("\nScaled train mean (should be ~0):", np.mean(X_train_scaled))
print("Scaled train std (should be ~1):", np.std(X_train_scaled))

# Save everything to disk
np.save('data/X_train.npy', X_train_scaled)
np.save('data/X_test.npy', X_test_scaled)
np.save('data/y_train.npy', y_train.values)
np.save('data/y_test.npy', y_test.values)

# Also save the final feature column names - useful later for the paper
# (e.g. listing which features the CNN actually used)
with open('data/feature_columns.txt', 'w') as f:
    f.write('\n'.join(X.columns.tolist()))

print("\nSaved scaled arrays and feature column list to data/ folder.")