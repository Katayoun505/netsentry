import numpy as np
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    confusion_matrix, classification_report, roc_auc_score
)
# Load the same preprocessed data used for the CNN
X_train = np.load('data/X_train.npy')
X_test = np.load('data/X_test.npy')
y_train = np.load('data/y_train.npy')
y_test = np.load('data/y_test.npy')
print("X_train shape:", X_train.shape)
print("X_test shape:", X_test.shape)
# Random Forest doesn't need the (samples, timesteps, channels) reshape the CNN needed -
# it works directly on flat feature vectors, which is part of why it's simpler to use
rf = RandomForestClassifier(
    n_estimators=100,   # number of trees
    max_depth=None,     # let trees grow fully
    random_state=42,
    n_jobs=-1           # use all CPU cores - RF trains much faster than a CNN
)
print("\nTraining Random Forest...")
start_time = time.time()
rf.fit(X_train, y_train)
train_time = time.time() - start_time
print(f"Training took {train_time:.2f} seconds")

import joblib
joblib.dump(rf, 'rf_model.pkl')
print("Saved trained model to rf_model.pkl")

# Predict
start_time = time.time()
y_pred = rf.predict(X_test)
y_pred_proba = rf.predict_proba(X_test)[:, 1]  # probability of class 1 (ATTACK)
inference_time = time.time() - start_time
print(f"Inference on test set took {inference_time:.2f} seconds")
# --- Same metrics as the CNN evaluation, for direct comparison ---
cm = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()
print("\nConfusion Matrix:")
print(cm)
print(f"\nTrue Negatives (correctly identified benign):  {tn}")
print(f"False Positives (benign flagged as attack):     {fp}")
print(f"False Negatives (attack missed, called benign): {fn}")
print(f"True Positives (correctly identified attack):   {tp}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK'], digits=4))
auc = roc_auc_score(y_test, y_pred_proba)
print(f"ROC-AUC Score: {auc:.4f}")
# --- Feature importance - a key advantage RF has over CNNs: interpretability ---
feature_names = open('data/feature_columns.txt').read().splitlines()
importances = rf.feature_importances_
top_features = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)[:10]
print("\nTop 10 most important features (Random Forest):")
for name, score in top_features:
    print(f"  {name}: {score:.4f}")
# Save timing + key metrics for your comparison table later
import pandas as pd
summary = pd.DataFrame([{
    'model': 'Random Forest',
    'train_time_sec': train_time,
    'inference_time_sec': inference_time,
    'accuracy': (tp + tn) / (tp + tn + fp + fn),
    'precision': tp / (tp + fp),
    'recall': tp / (tp + fn),
    'auc': auc
}])
summary.to_csv('rf_results.csv', index=False)
print("\nSaved summary to rf_results.csv")