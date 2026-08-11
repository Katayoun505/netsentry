import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
)
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

# --- Load and clean data (same steps as split_data.py) ---
df = pd.read_csv('data/Wednesday_cleaned.csv')
df = df[df['Label'] != 'Heartbleed'].reset_index(drop=True)

X = df.drop(columns=['Label'])
y = df['Label']
y_binary = (y != 'BENIGN').astype(int).values

# Drop zero-variance columns
zero_var_cols = X.columns[X.nunique() == 1].tolist()
X = X.drop(columns=zero_var_cols)
X = X.values  # convert to numpy array

print(f"Data shape: {X.shape}, zero-variance columns dropped: {len(zero_var_cols)}")

def build_model(input_dim):
    model = keras.Sequential([
        layers.Input(shape=(input_dim, 1)),
        layers.Conv1D(filters=32, kernel_size=3, activation='relu'),
        layers.MaxPooling1D(pool_size=2),
        layers.Conv1D(filters=64, kernel_size=3, activation='relu'),
        layers.MaxPooling1D(pool_size=2),
        layers.Flatten(),
        layers.Dense(64, activation='relu'),
        layers.Dropout(0.3),
        layers.Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model

# --- 5-Fold Stratified Cross-Validation ---
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

fold_results = []

for fold_idx, (train_idx, val_idx) in enumerate(skf.split(X, y_binary), start=1):
    print(f"\n{'='*50}")
    print(f"FOLD {fold_idx}/5")
    print(f"{'='*50}")

    X_train_fold, X_val_fold = X[train_idx], X[val_idx]
    y_train_fold, y_val_fold = y_binary[train_idx], y_binary[val_idx]

    # Scale - fit ONLY on this fold's training data
    scaler = StandardScaler()
    X_train_fold_scaled = scaler.fit_transform(X_train_fold)
    X_val_fold_scaled = scaler.transform(X_val_fold)

    # Reshape for Conv1D
    X_train_fold_cnn = X_train_fold_scaled.reshape(X_train_fold_scaled.shape[0], X_train_fold_scaled.shape[1], 1)
    X_val_fold_cnn = X_val_fold_scaled.reshape(X_val_fold_scaled.shape[0], X_val_fold_scaled.shape[1], 1)

    # Fresh model each fold
    model = build_model(X_train_fold_cnn.shape[1])

    model.fit(
        X_train_fold_cnn, y_train_fold,
        epochs=10,
        batch_size=256,
        verbose=0  # silent per-epoch, we just want the final fold result
    )

    # Predict on this fold's validation set
    y_pred_proba = model.predict(X_val_fold_cnn, verbose=0).flatten()
    y_pred = (y_pred_proba >= 0.5).astype(int)

    acc = accuracy_score(y_val_fold, y_pred)
    prec = precision_score(y_val_fold, y_pred)
    rec = recall_score(y_val_fold, y_pred)
    f1 = f1_score(y_val_fold, y_pred)
    auc = roc_auc_score(y_val_fold, y_pred_proba)

    print(f"Fold {fold_idx} -> Accuracy: {acc:.4f}, Precision: {prec:.4f}, Recall: {rec:.4f}, F1: {f1:.4f}, AUC: {auc:.4f}")

    fold_results.append({'accuracy': acc, 'precision': prec, 'recall': rec, 'f1': f1, 'auc': auc})

# --- Aggregate results across all 5 folds ---
results_df = pd.DataFrame(fold_results)

print(f"\n{'='*50}")
print("CROSS-VALIDATION SUMMARY (5 folds)")
print(f"{'='*50}")
print(results_df)

print("\nMean ± Std across folds:")
for metric in ['accuracy', 'precision', 'recall', 'f1', 'auc']:
    mean = results_df[metric].mean()
    std = results_df[metric].std()
    print(f"{metric.capitalize():10s}: {mean:.4f} ± {std:.4f}")

# Save results for later use in the paper
results_df.to_csv('cv_results.csv', index=False)
print("\nSaved fold-by-fold results to cv_results.csv")