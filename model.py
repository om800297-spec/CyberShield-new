
import re
from urllib.parse import urlparse

def _risk(reasons):
    if len(reasons) >= 3:
        return "HIGH"
    if len(reasons) == 2:
        return "MEDIUM"
    return "LOW"

def analyze_text(value, scan_type="message"):
    reasons = []
    if re.search(r"\b(otp|cvv|pin|password|passcode)\b", value, re.I):
        reasons.append("Sensitive credential or payment information is requested.")
    if re.search(r"(urgent|immediately|verify now|account.*(blocked|suspended)|expire)", value, re.I):
        reasons.append("Urgency or account-pressure language detected.")
    if re.search(r"https?://|www\.", value, re.I):
        reasons.append("External link detected; verify its destination independently.")
    if re.search(r"\b(bank|upi|kyc|refund|cashback|payment)\b", value, re.I):
        reasons.append("Financial-service language detected.")
    if re.search(r"\b(lottery|winner|prize|reward)\b", value, re.I):
        reasons.append("Prize/reward scam pattern detected.")

    risk = _risk(reasons)
    return {
        "type": scan_type,
        "risk": risk,
        "reasons": reasons or ["No obvious indicator detected by the current rules."],
        "recommendation": (
            "Do not click suspicious links or share OTP, PIN, CVV or passwords. "
            "Verify through an independently opened official channel."
            if risk == "HIGH" else
            "Verify the sender and destination independently before taking action."
        )
    }

def analyze_url(value):
    reasons = []
    try:
        parsed = urlparse(value if "://" in value else "https://" + value)
        host = parsed.hostname or ""
        if parsed.scheme != "https":
            reasons.append("URL does not use HTTPS.")
        if "@" in value:
            reasons.append("URL contains an @ character, which can be misleading.")
        if len(host) > 45:
            reasons.append("Unusually long hostname.")
        if re.search(r"(login|verify|secure|account|bank|kyc|wallet)", value, re.I):
            reasons.append("Sensitive-account keywords appear in the URL.")
    except Exception:
        reasons.append("URL could not be parsed.")
    return {"type":"url","risk":_risk(reasons),"reasons":reasons or ["No obvious structural red flag detected."],
            "recommendation":"Do not enter credentials unless the domain has been independently verified."}

def analyze_email(value):
    valid = bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value))
    reasons = [] if valid else ["Email address format appears invalid."]
    if valid and re.search(r"(mailinator|tempmail|10minutemail)", value, re.I):
        reasons.append("Disposable-email domain pattern detected.")
    return {"type":"email","risk":_risk(reasons),"reasons":reasons or ["Basic email format looks valid."],
            "recommendation":"For production, add server-side domain and reputation checks."}

def analyze_phone(value):
    cleaned = re.sub(r"[\s().-]", "", value)
    reasons = []
    if not re.fullmatch(r"\+?\d{8,15}", cleaned):
        reasons.append("Phone number format could not be validated.")
    if cleaned.startswith("+") and not cleaned.startswith(("+91","+1","+44","+61","+971")):
        reasons.append("Country code is outside the demo's common examples.")
    return {"type":"phone","risk":_risk(reasons),"reasons":reasons or ["Basic phone-number structure looks valid."],
            "recommendation":"For production, connect an authorized phone reputation provider."}

def analyze_ip(value):
    ok = False
    try:
        parts = value.split(".")
        ok = len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        ok = False
    reasons = [] if ok else ["Input is not a valid IPv4 address."]
    return {"type":"ip","risk":_risk(reasons),"reasons":reasons or ["IPv4 format is valid."],
            "recommendation":"For production, connect an authorized IP reputation/ASN service."}
