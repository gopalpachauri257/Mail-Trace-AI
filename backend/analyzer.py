
import hashlib
import ipaddress
import os
import re
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime

try:
    import joblib
except Exception:
    joblib = None


URL_RE = re.compile(r"""https?://[^\s<>"']+""", re.I)

IP_RE = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
)

DOMAIN_RE = re.compile(
    r"(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.I,
)

KEYWORDS = {
    "verify": 8,
    "verification": 8,
    "urgent": 8,
    "suspend": 10,
    "suspended": 10,
    "password": 5,
    "login": 5,
    "account": 4,
    "invoice": 5,
    "payment": 5,
    "click": 5,
    "confirm": 5,
    "security alert": 8,
    "wire transfer": 12,
    "gift card": 10,
    "bank": 4,
    "credential": 8,
    "reset": 5,
    "immediately": 5,
}

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "ml",
    "email_threat_model.joblib",
)

_MODEL = None


def safe_ip(value):
    try:
        return ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return None


def is_public_ip(value):
    obj = safe_ip(value)
    return bool(obj and obj.is_global)


def extract_body(msg):
    parts = []

    if msg.is_multipart():
        for part in msg.walk():
            if (
                part.get_content_type() == "text/plain"
                and part.get_content_disposition() != "attachment"
            ):
                try:
                    parts.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            content = msg.get_content()
            if isinstance(content, str):
                parts.append(content)
        except Exception:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    parts.append(payload.decode(errors="replace"))
            except Exception:
                pass

    return "\n".join(parts).strip()


def auth_status(msg):
    auth_headers = msg.get_all("Authentication-Results", [])
    spf_headers = msg.get_all("Received-SPF", [])
    text = " ".join(str(value) for value in auth_headers + spf_headers)

    def status(name):
        match = re.search(
            rf"\b{name}\s*=\s*"
            r"(pass|fail|softfail|neutral|none|temperror|permerror)\b",
            text,
            re.I,
        )

        return match.group(1).upper() if match else "UNKNOWN"

    return {
        name: status(name)
        for name in ("spf", "dkim", "dmarc")
    }


def parse_received(msg):
    hops = []

    for raw in msg.get_all("Received", []):
        ips = [
            ip for ip in IP_RE.findall(str(raw))
            if safe_ip(ip) is not None
        ]

        public = [ip for ip in ips if is_public_ip(ip)]

        hops.append({
            "raw": str(raw),
            "ips": list(dict.fromkeys(ips)),
            "public_ips": list(dict.fromkeys(public)),
        })

    return hops


def _load_model():
    global _MODEL

    if _MODEL is not None or joblib is None:
        return _MODEL

    if os.path.exists(MODEL_PATH):
        try:
            _MODEL = joblib.load(MODEL_PATH)
        except Exception:
            _MODEL = None

    return _MODEL


def ml_prediction(text):
    model = _load_model()

    if model is None:
        return {
            "classification": "RULE-BASED",
            "confidence": None,
            "model": "Forensic rule baseline",
            "reasons": [],
        }

    try:
        prediction = model.predict([text])[0]
        label_text = str(prediction).strip().upper()

        label = (
            "PHISHING"
            if label_text in ("1", "PHISHING")
            else "NORMAL"
        )

        confidence = None

        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba([text])[0]
            classes = list(model.classes_)

            predicted_index = classes.index(prediction)
            confidence = float(probabilities[predicted_index]) * 100.0

        reasons = []

        for term in (
            "verify",
            "password",
            "login",
            "urgent",
            "suspended",
            "payment",
            "invoice",
            "credential",
            "click",
        ):
            if term in text.lower():
                reasons.append(term)

        return {
            "classification": label,
            "confidence": confidence,
            "model": "TF-IDF + Logistic Regression",
            "reasons": reasons,
        }

    except Exception:
        return {
            "classification": "RULE-BASED",
            "confidence": None,
            "model": "Forensic rule baseline",
            "reasons": [],
        }


def analyze_eml(data: bytes, filename: str):
    msg = BytesParser(policy=policy.default).parsebytes(data)

    body = extract_body(msg)
    subject = str(msg.get("Subject", ""))
    sender = str(msg.get("From", ""))
    reply = str(msg.get("Reply-To", ""))
    return_path = str(msg.get("Return-Path", ""))

    auth = auth_status(msg)
    received = parse_received(msg)
    text = (subject + "\n" + body).lower()

    urls = list(dict.fromkeys(
        URL_RE.findall(body + "\n" + str(msg))
    ))

    ips = list(dict.fromkeys(
        IP_RE.findall(
            body + "\n" + "\n".join(
                hop["raw"] for hop in received
            )
        )
    ))

    ips = [ip for ip in ips if safe_ip(ip) is not None]

    domains = list(dict.fromkeys(
        DOMAIN_RE.findall(
            body + "\n" + sender + "\n" + reply
            + "\n" + return_path + "\n" + "\n".join(urls)
        )
    ))

    score = 0
    reasons = []

    for keyword, weight in KEYWORDS.items():
        if keyword in text:
            score += weight
            reasons.append(f"Suspicious language: {keyword}")

    for name, value in auth.items():
        if value == "FAIL":
            score += 12
            reasons.append(f"{name.upper()} authentication failed")
        elif value == "SOFTFAIL":
            score += 7
            reasons.append(
                f"{name.upper()} authentication soft-failed"
            )

    if urls:
        score += min(20, 5 * len(urls))
        reasons.append(f"{len(urls)} URL(s) extracted")

    def addr(value):
        match = re.search(r"<([^>]+)>", value)
        return (match.group(1) if match else value).strip().lower()

    if reply and sender:
        sender_addr = addr(sender)
        reply_addr = addr(reply)

        if "@" in sender_addr and "@" in reply_addr:
            sender_domain = sender_addr.rsplit("@", 1)[1]
            reply_domain = reply_addr.rsplit("@", 1)[1]

            if sender_domain != reply_domain:
                score += 10
                reasons.append(
                    "Reply-To domain differs from sender domain"
                )

    if len(received) >= 4:
        score += 8
        reasons.append("Long SMTP relay chain")

    score = min(100, score)

    level = (
        "HIGH" if score >= 70
        else "MEDIUM" if score >= 40
        else "LOW"
    )

    sha = hashlib.sha256(data).hexdigest()

    try:
        date_iso = (
            parsedate_to_datetime(str(msg.get("Date"))).isoformat()
            if msg.get("Date")
            else None
        )
    except Exception:
        date_iso = str(msg.get("Date")) if msg.get("Date") else None

    public_ips = list(dict.fromkeys(
        ip for ip in ips if is_public_ip(ip)
    ))

    ml = ml_prediction(subject + "\n" + body)

    return {
        "file": {
            "name": filename,
            "size_bytes": len(data),
            "sha256": sha,
        },
        "email": {
            "from": sender,
            "to": str(msg.get("To", "")),
            "subject": subject,
            "date": str(msg.get("Date", "")),
            "date_iso": date_iso,
            "reply_to": reply,
            "return_path": return_path,
        },
        "authentication": auth,
        "indicators": {
            "urls": urls,
            "ips": ips,
            "public_ips": public_ips,
            "domains": domains,
        },
        "risk": {
            "score": score,
            "level": level,
            "reasons": reasons,
        },
        "ml": ml,
        "relay_path": received,
        "body_preview": body[:5000],
        "forensics": {
            "header_count": len(msg.items()),
            "received_count": len(received),
            "mime_type": msg.get_content_type(),
        },
    }
