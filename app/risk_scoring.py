
def calculate_risk(event_count: int, suspicious: bool) -> dict:
    """
    Calculate a demo risk score from 0 to 100.
    This is a prototype rule, not a calibrated threat model.
    """
    score = 0
    reasons = []

    if suspicious:
        score += 50
        reasons.append("Suspicious activity detected")

    if event_count >= 5:
        score += 30
        reasons.append("Repeated activity threshold reached")

    if event_count >= 10:
        score += 20
        reasons.append("Very high event volume")

    score = min(score, 100)

    if score >= 70:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "risk_score": score,
        "severity": severity,
        "reasons": reasons or ["No significant risk indicators"],
    }
