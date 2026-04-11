# triage_engine.py
# Author: Yuva
# Purpose: Analyses parsed log events and assigns a severity score
# This is the "brain" of the system - it decides how dangerous each event is


EVENT_SCORES = {
    # SSH events
    "SSH_FAILED_LOGIN": 30,
    "SSH_INVALID_USER": 40,
    "SSH_SUCCESSFUL_LOGIN": 10,
    "SUDO_COMMAND": 50,
    "SSH_OTHER": 5,

    # Firewall events
    "FIREWALL_BLOCK_SENSITIVE_PORT": 60,
    "FIREWALL_BLOCK": 25,
    "FIREWALL_ALLOW": 5,

    # Web server events
    "WEB_UNAUTHORISED_ACCESS": 40,
    "WEB_PATH_TRAVERSAL": 80,
    "WEB_SERVER_ERROR": 20,
    "WEB_POST_SUCCESS": 10,
    "WEB_NORMAL": 5,
}

# Severity level thresholds
# If score is 0-29  - LOW
# If score is 30-59  - MEDIUM
# If score is 60-79  - HIGH
# If score is 80+    - CRITICAL
SEVERITY_LEVELS = {
    "CRITICAL": 80,
    "HIGH": 60,
    "MEDIUM": 30,
    "LOW": 0,
}

# IPs that are always treated as suspicious regardless of event type
KNOWN_MALICIOUS_IPS = [
    "45.33.32.156",
    "198.51.100.77",
    "203.0.113.99",
]



def get_base_score(event_type):
    """
    Looks up the base score for a given event type.
    Returns 5 as a default if the event type is not in our list.
    """
    return EVENT_SCORES.get(event_type, 5)


def apply_ip_bonus(score, source_ip):
    """
    Adds extra points if the source IP is on the known malicious list.
    This is called a 'threat intelligence boost'.
    """
    if source_ip in KNOWN_MALICIOUS_IPS:
        
        score += 30
    return score


def apply_repeat_penalty(score, source_ip, all_events):
    """
    Adds extra points if the same IP appears many times.
    Many failed logins from one IP = brute force attack.
    """
    ip_count = sum(1 for e in all_events if e.get("source_ip") == source_ip)

    if ip_count > 5:
        score += 20
    elif ip_count > 10:
        score += 40

    return score


def get_severity_label(score):
    """
    Converts a numeric score into a severity label.
    Checks from highest to lowest threshold.
    """
    if score >= SEVERITY_LEVELS["CRITICAL"]:
        return "CRITICAL"
    elif score >= SEVERITY_LEVELS["HIGH"]:
        return "HIGH"
    elif score >= SEVERITY_LEVELS["MEDIUM"]:
        return "MEDIUM"
    else:
        return "LOW"


# MAIN  FUNCTION

def triage_event(event, all_events):
    """
    Takes a single parsed log event and calculates its final severity.
    
    Steps:
    1. Get the base score from the event type
    2. Add bonus if IP is known malicious
    3. Add bonus if same IP repeated many times (brute force detection)
    4. Cap the score at 100
    5. Convert score to severity label
    6. Return the enriched event dictionary
    
    'event' is a dictionary from log_parser.py
    'all_events' is the full list - needed to check repeat IPs
    """

    event_type = event.get("event_type", "UNKNOWN")
    source_ip = event.get("source_ip", "unknown")

    score = get_base_score(event_type)

    score = apply_ip_bonus(score, source_ip)

    score = apply_repeat_penalty(score, source_ip, all_events)

    score = min(score, 100)

    severity = get_severity_label(score)

    event["score"] = score
    event["severity"] = severity

    return event


def triage_all_events(events):
    """
    Runs triage on every event in a list.
    Returns the full list with score and severity added to each event.
    """
    triaged = []

    for event in events:
        triaged_event = triage_event(event, events)
        triaged.append(triaged_event)

    return triaged


def get_summary(triaged_events):
    """
    Produces a summary dictionary counting events by severity.
    Used by the dashboard to show totals.
    """
    summary = {
        "total": len(triaged_events),
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for event in triaged_events:
        severity = event.get("severity", "LOW")
        if severity in summary:
            summary[severity] += 1

    return summary


if __name__ == "__main__":
    from log_parser import parse_log_file

    print("=== Running Triage Engine Test ===\n")

    ssh_events = parse_log_file("sample_logs/auth.log", "ssh")
    fw_events = parse_log_file("sample_logs/firewall.log", "firewall")
    apache_events = parse_log_file("sample_logs/apache_access.log", "apache")

    all_events = ssh_events + fw_events + apache_events

    triaged = triage_all_events(all_events)

    for event in triaged:
        print(f"[{event['severity']}] Score: {event['score']} | "
              f"Type: {event['event_type']} | "
              f"IP: {event['source_ip']}")

    print("\n=== Summary ===")
    summary = get_summary(triaged)
    for key, value in summary.items():
        print(f"{key}: {value}")