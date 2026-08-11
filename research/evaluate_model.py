import numpy as np
from tensorflow import keras
from sklearn.metrics import (
    confusion_matrix, classification_report,
    roc_auc_score, roc_curve, precision_recall_curve
)
import matplotlib.pyplot as plt

# Load test data
X_test = np.load('data/X_test.npy')
y_test = np.load('data/y_test.npy')

# Reshape for CNN input
X_test_cnn = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)

# Load the trained model
model = keras.models.load_model('cnn_model.keras')

# Get predictions (probabilities, then convert to 0/1 using 0.5 threshold)
y_pred_proba = model.predict(X_test_cnn, verbose=0).flatten()
y_pred = (y_pred_proba >= 0.5).astype(int)

# --- Confusion Matrix ---
cm = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()

print("Confusion Matrix:")
print(cm)
print(f"\nTrue Negatives (correctly identified benign):  {tn}")
print(f"False Positives (benign flagged as attack):     {fp}")
print(f"False Negatives (attack missed, called benign): {fn}")
print(f"True Positives (correctly identified attack):   {tp}")

# --- Classification Report: precision, recall, F1 ---
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['BENIGN', 'ATTACK'], digits=4))

# --- ROC-AUC ---
auc = roc_auc_score(y_test, y_pred_proba)
print(f"ROC-AUC Score: {auc:.4f}")

# --- Save ROC curve plot ---
fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
plt.figure(figsize=(6, 5))
plt.plot(fpr, tpr, label=f'CNN (AUC = {auc:.4f})')
plt.plot([0, 1], [0, 1], linestyle='--', color='gray', label='Random guess')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('ROC Curve - CNN Binary IDS')
plt.legend()
plt.tight_layout()
plt.savefig('cnn_roc_curve.png', dpi=150)
print("\nSaved ROC curve to cnn_roc_curve.png")