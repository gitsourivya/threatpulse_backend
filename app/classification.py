
def classify_event(event: dict, detection: dict) -> dict:
    """
    Basic rule-based classification for the Threat Pulse prototype.
    These are indicators, not definitive proof of an attack.
    """

    source_port = event["source_port"]
    destination_port = event["destination_port"]
    protocol = event["protocol"].upper()

    if detection["suspicious"]:
        attack_type = "REPEATED_ACTIVITY"
        confidence = "MEDIUM"
        description = (
            "Repeated events from the same source IP "
            "crossed the detection threshold."
        )

    elif destination_port in (22, 23, 3389):
        attack_type = "REMOTE_ACCESS_ACTIVITY"
        confidence = "LOW"
        description = (
            "Traffic targets a remote-access service. "
            "This alone does not indicate an attack."
        )

    elif destination_port in (80, 443, 8080, 8443):
        attack_type = "WEB_TRAFFIC"
        confidence = "LOW"
        description = "Traffic targets a common web-service port."

    elif protocol not in ("TCP", "UDP", "ICMP"):
        attack_type = "UNCOMMON_PROTOCOL"
        confidence = "LOW"
        description = "The event uses a protocol outside the basic allowlist."

    else:
        attack_type = "NORMAL_ACTIVITY"
        confidence = "LOW"
        description = "No known suspicious pattern matched the current rules."

    return {
        "attack_type": attack_type,
        "confidence": confidence,
        "description": description,
    }
  