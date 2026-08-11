import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

# Load the preprocessed data
X_train = np.load('data/X_train.npy')
X_test = np.load('data/X_test.npy')
y_train = np.load('data/y_train.npy')
y_test = np.load('data/y_test.npy')

print("X_train shape:", X_train.shape)
print("X_test shape:", X_test.shape)

# Conv1D expects input shape (samples, timesteps, channels)
# Our 68 features become 68 "timesteps" with 1 channel each
X_train_cnn = X_train.reshape(X_train.shape[0], X_train.shape[1], 1)
X_test_cnn = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)

print("Reshaped for CNN:", X_train_cnn.shape)

# Build a simple 1D-CNN
model = keras.Sequential([
    layers.Input(shape=(X_train_cnn.shape[1], 1)),
    layers.Conv1D(filters=32, kernel_size=3, activation='relu'),
    layers.MaxPooling1D(pool_size=2),
    layers.Conv1D(filters=64, kernel_size=3, activation='relu'),
    layers.MaxPooling1D(pool_size=2),
    layers.Flatten(),
    layers.Dense(64, activation='relu'),
    layers.Dropout(0.3),
    layers.Dense(1, activation='sigmoid')  # binary output: 0=benign, 1=attack
])

model.compile(
    optimizer='adam',
    loss='binary_crossentropy',
    metrics=['accuracy']
)

model.summary()

# Train the model
history = model.fit(
    X_train_cnn, y_train,
    validation_split=0.1,   # hold out 10% of training data to monitor overfitting
    epochs=10,
    batch_size=256,
    verbose=1
)

# Evaluate on the held-out test set
test_loss, test_accuracy = model.evaluate(X_test_cnn, y_test, verbose=0)
print(f"\nTest Loss: {test_loss:.4f}")
print(f"Test Accuracy: {test_accuracy:.4f}")

# Save the trained model so we don't have to retrain every time
model.save('cnn_model.keras')
print("\nModel saved to cnn_model.keras")