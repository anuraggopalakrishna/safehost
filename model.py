import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
import warnings

warnings.filterwarnings("ignore")


# Load and preprocess data
def load_and_preprocess(filepath):
    df = pd.read_csv(filepath)

    # Select features
    features = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Fwd Packets Length Total",
        "Bwd Packets Length Total",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Flow IAT Mean",
        "Fwd IAT Mean",
        "Bwd IAT Mean",
        "Fwd Header Length",
        "Bwd Header Length",
        "Packet Length Mean",
        "FIN Flag Count",
        "SYN Flag Count",
        "ACK Flag Count",
        "Init Fwd Win Bytes",
        "Init Bwd Win Bytes",
        "Label",
    ]

    df = df[features]

    # Clean data
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # Encode labels
    le = LabelEncoder()
    df["Label"] = le.fit_transform(df["Label"])

    return df, le


# Train model
def train_model(df):
    X = df.drop("Label", axis=1)
    y = df["Label"]

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # Scale features
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    # Train Random Forest
    model = RandomForestClassifier(
        n_estimators=100, max_depth=10, random_state=42, class_weight="balanced"
    )
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    print("Model Accuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    return model, scaler


# Save model
def save_model(model, scaler, label_encoder, filename="model.pkl"):
    joblib.dump(
        {"model": model, "scaler": scaler, "label_encoder": label_encoder}, filename
    )


# Main training process
if __name__ == "__main__":
    # Load your dataset
    df, le = load_and_preprocess("dataset.csv")

    # Train and save model
    model, scaler = train_model(df)
    save_model(model, scaler, le)
    print("Model trained and saved successfully!")


