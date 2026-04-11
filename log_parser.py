# log_parser.py
# Author: Yuva
# Purpose: Reads raw log files and extracts structured data from each line
# Uses Python

import re
from datetime import datetime



SSH_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+(?P<message>.+)'
)

IP_PATTERN = re.compile(
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
)

FIREWALL_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+kernel:.*\[UFW (?P<action>\w+)\].*SRC=(?P<src_ip>[\d.]+).*DPT=(?P<port>\d+)'
)

APACHE_PATTERN = re.compile(
    r'(?P<ip>[\d.]+)\s+-\s+-\s+\[(?P<datetime>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+(?P<status>\d+)'
)



def parse_ssh_line(line):
    """
    Parses a single SSH auth log line.
    Returns a dictionary with event details, or None if line doesn't match.
    """
    match = SSH_PATTERN.match(line)
    if not match:
        return None

    message = match.group("message")
    timestamp = f"{match.group('month')} {match.group('day')} {match.group('time')}"

    ip_match = IP_PATTERN.search(message)
    source_ip = ip_match.group(1) if ip_match else "unknown"

    if "Failed password" in message:
        event_type = "SSH_FAILED_LOGIN"
    elif "Accepted password" in message or "Accepted publickey" in message:
        event_type = "SSH_SUCCESSFUL_LOGIN"
    elif "invalid user" in message:
        event_type = "SSH_INVALID_USER"
    elif "sudo" in message:
        event_type = "SUDO_COMMAND"
    else:
        event_type = "SSH_OTHER"

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "event_type": event_type,
        "raw_log": line.strip(),
        "log_source": "auth.log"
    }


def parse_firewall_line(line):
    """
    Parses a single UFW firewall log line.
    Returns a dictionary with event details, or None if line doesn't match.
    """
    match = FIREWALL_PATTERN.match(line)
    if not match:
        return None

    timestamp = f"{match.group('month')} {match.group('day')} {match.group('time')}"
    action = match.group("action")  
    source_ip = match.group("src_ip")
    port = match.group("port")

    if action == "BLOCK":
        sensitive_ports = ["22", "3389", "445", "8080", "3306", "23"]
        if port in sensitive_ports:
            event_type = "FIREWALL_BLOCK_SENSITIVE_PORT"
        else:
            event_type = "FIREWALL_BLOCK"
    else:
        event_type = "FIREWALL_ALLOW"

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "event_type": event_type,
        "raw_log": line.strip(),
        "log_source": "firewall.log",
        "port": port
    }


def parse_apache_line(line):
    """
    Parses a single Apache access log line.
    Returns a dictionary with event details, or None if line doesn't match.
    """
    match = APACHE_PATTERN.match(line)
    if not match:
        return None

    source_ip = match.group("ip")
    timestamp = match.group("datetime")
    method = match.group("method")
    path = match.group("path")
    status = match.group("status")

    if status == "401" or status == "403":
        event_type = "WEB_UNAUTHORISED_ACCESS"
    elif any(keyword in path for keyword in ["/etc/passwd", "/etc/shadow", "../", ".env", "/admin"]):
        event_type = "WEB_PATH_TRAVERSAL"
    elif status.startswith("5"):
        event_type = "WEB_SERVER_ERROR"
    elif method == "POST" and status == "200":
        event_type = "WEB_POST_SUCCESS"
    else:
        event_type = "WEB_NORMAL"

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "event_type": event_type,
        "raw_log": line.strip(),
        "log_source": "apache_access.log",
        "http_status": status,
        "path": path
    }



def parse_log_file(filepath, log_type):
    """
    Reads a log file and parses every line.
    log_type must be one of: 'ssh', 'firewall', 'apache'
    Returns a list of parsed event dictionaries.
    """
    parsed_events = []

    try:
        with open(filepath, "r") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                if log_type == "ssh":
                    result = parse_ssh_line(line)
                elif log_type == "firewall":
                    result = parse_firewall_line(line)
                elif log_type == "apache":
                    result = parse_apache_line(line)
                else:
                    result = None

                if result:
                    parsed_events.append(result)

    except FileNotFoundError:
        print(f"[PARSER] File not found: {filepath}")

    return parsed_events


if __name__ == "__main__":
    print("=== Testing SSH Log Parser ===")
    ssh_events = parse_log_file("sample_logs/auth.log", "ssh")
    for event in ssh_events:
        print(event)

    print("\n=== Testing Firewall Log Parser ===")
    fw_events = parse_log_file("sample_logs/firewall.log", "firewall")
    for event in fw_events:
        print(event)

    print("\n=== Testing Apache Log Parser ===")
    apache_events = parse_log_file("sample_logs/apache_access.log", "apache")
    for event in apache_events:
        print(event)

    print(f"\n[PARSER] Total events parsed: {len(ssh_events) + len(fw_events) + len(apache_events)}")