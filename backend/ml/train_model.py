from pathlib import Path
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "dataset" / "enron_data_fraud_labeled 2.csv"
OUTPUT = Path(__file__).resolve().parent / "email_threat_model.joblib"
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

df = pd.read_csv(DATASET, usecols=["Subject", "Body", "Label"])
df["Subject"] = df["Subject"].fillna("")
df["Body"] = df["Body"].fillna("")
df["text"] = df["Subject"] + "\n" + df["Body"]
df = df.drop_duplicates(subset=["text"])
df = df[df["Label"].isin([0, 1])]

X_train, X_test, y_train, y_test = train_test_split(
    df["text"],
    df["Label"],
    test_size=0.20,
    random_state=42,
    stratify=df["Label"]
)

model = Pipeline([
    ("tfidf", TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        min_df=2,
        max_features=100000,
        sublinear_tf=True
    )),
    ("clf", LogisticRegression(
        max_iter=2000,
        class_weight="balanced",
        random_state=42
    ))
])

model.fit(X_train, y_train)
pred = model.predict(X_test)

print(f"Rows used: {len(df):,}")
print(f"Accuracy: {accuracy_score(y_test, pred):.4f}")
print(classification_report(y_test, pred, target_names=["NORMAL", "PHISHING"]))

joblib.dump(model, OUTPUT)
print(f"Saved model to: {OUTPUT}")
