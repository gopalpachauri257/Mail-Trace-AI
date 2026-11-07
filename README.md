# MailForensic AI v2

A runnable email-forensics MVP for `.eml` evidence. It provides header/content analysis, SPF/DKIM/DMARC extraction, explainable risk scoring, optional ML classification, IOC extraction, SMTP relay reconstruction, SHA-256 evidence integrity, public-IP infrastructure lookup, correlation graph, and PDF forensic reporting.

## 1. Run on macOS

```bash
cd "MailForensic_AI_Final 2"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r backend/requirements.txt
uvicorn backend.main:app --reload
```

Keep the backend terminal running.

Then open `frontend/index.html` with VS Code Live Server.

Backend health:
`http://127.0.0.1:8000/api/health`

API docs:
`http://127.0.0.1:8000/docs`

## 2. Features

- `.eml` upload / drag and drop
- Header + body parsing
- SPF / DKIM / DMARC result extraction
- Rule-based forensic risk score
- Optional TF-IDF + Logistic Regression model
- Human-readable ML explanation
- URL / IP / domain IOC extraction
- SMTP `Received` relay path
- Public IP infrastructure lookup
- Correlation graph
- SHA-256 evidence hash
- Downloadable PDF forensic report
- Built-in illustrative phishing sample

## 3. Optional ML training

The project works without a trained model and will show the rule-based baseline.

To train the included model:

```bash
python backend/ml/train_model.py
```

The model is saved as:

```text
backend/ml/email_threat_model.joblib
```

The dataset is an Enron-derived labeled fraud corpus. Test-set metrics from one training run are dataset-specific and should not be presented as real-world detection accuracy.

## 4. Important scope

- IP geolocation is approximate infrastructure intelligence, not proof of a sender's physical location.
- Cloud, VPN, proxy and relay infrastructure can make location attribution misleading.
- Authentication results are extracted from headers; the tool does not independently perform live SPF/DKIM/DMARC verification.
- The built-in sample uses documentation/example domains and IP ranges.
- Threat scoring is a forensic aid, not a final attribution or legal conclusion.
