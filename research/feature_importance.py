import joblib
import pandas as pd
import matplotlib.pyplot as plt

# Load trained Random Forest
rf = joblib.load("rf_model.pkl")

# Load feature names
with open("data/feature_columns.txt", "r") as f:
    feature_names = [line.strip() for line in f]

# Create importance table
importance = pd.DataFrame({
    "Feature": feature_names,
    "Importance": rf.feature_importances_
})

importance = importance.sort_values(
    by="Importance",
    ascending=False
)

print("\nTop 20 Features:\n")
print(importance.head(20))

importance.to_csv(
    "feature_importance.csv",
    index=False
)

# Plot top 20
top20 = importance.head(20)

plt.figure(figsize=(10,7))
plt.barh(top20["Feature"], top20["Importance"])
plt.gca().invert_yaxis()

plt.xlabel("Feature Importance")
plt.title("Random Forest Feature Importance")

plt.tight_layout()
plt.savefig(
    "feature_importance.png",
    dpi=300
)

print("\nSaved:")
print("feature_importance.csv")
print("feature_importance.png")