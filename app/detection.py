
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta

# Store recent event timestamps for each source IP
event_history = defaultdict(deque)

# Detection settings
TIME_WINDOW_SECONDS = 60
EVENT_THRESHOLD = 5


def analyze_event(event: dict):
    source_ip = event["source_ip"]

    # Parse the event timestamp; use current UTC time if invalid
    try:
        timestamp = datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        timestamp = timestamp.astimezone(timezone.utc)

    except (ValueError, TypeError, AttributeError):
        timestamp = datetime.now(timezone.utc)

    cutoff = timestamp - timedelta(seconds=TIME_WINDOW_SECONDS)
    history = event_history[source_ip]

    # Remove events older than the time window
    while history and history[0] < cutoff:
        history.popleft()

    # Record this event
    history.append(timestamp)

    # Flag repeated activity within the window
    if len(history) >= EVENT_THRESHOLD:
        return {
            "suspicious": True,
            "reason": (
                f"{len(history)} events from the same IP "
                f"within {TIME_WINDOW_SECONDS} seconds"
            ),
        }

    return {
        "suspicious": False,
        "reason": "No threshold reached",
    }
