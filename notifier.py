# notifier.py
# Author: Yuva
# Purpose: Sends email alerts when CRITICAL severity events are detected

import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime


SENDER_EMAIL    = "your_gmail@gmail.com"
SENDER_PASSWORD = "your_app_password"
RECEIVER_EMAIL  = "your_gmail@gmail.com"

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT   = 587

EMAIL_ENABLED = False



def build_email_body(critical_events):
    """
    Builds the email message body from a list of critical events.
    Returns a plain text string listing each event.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Start with a header
    body = f"""
SECURITY ALERT — CRITICAL EVENTS DETECTED
==========================================
Time: {now}
Total Critical Events: {len(critical_events)}

DETAILS:
"""

    for i, event in enumerate(critical_events, start=1):
        body += f"""
Event {i}:
  Type      : {event.get('event_type', 'UNKNOWN')}
  Source IP : {event.get('source_ip', 'unknown')}
  Score     : {event.get('score', 0)}
  Timestamp : {event.get('timestamp', 'unknown')}
  Log Source: {event.get('log_source', 'unknown')}
  Raw Log   : {event.get('raw_log', '')[:100]}
"""

    body += "\n==========================================\n"
    body += "Automated Security Log Triage System — DBS MSc Cybersecurity\n"

    return body


def send_alert_email(critical_events):
    """
    Sends an email alert listing all critical events.
    Only sends if EMAIL_ENABLED is True.

    Returns True if email was sent successfully.
    Returns False if sending failed or email is disabled.
    """

    if not EMAIL_ENABLED:
        print("[NOTIFIER] Email alerts are disabled. Set EMAIL_ENABLED = True to enable.")
        return False

    if not critical_events:
        print("[NOTIFIER] No critical events to report.")
        return False

    try:
        message = MIMEMultipart("alternative")
        message["Subject"] = f"🚨 CRITICAL ALERT — {len(critical_events)} Critical Security Events Detected"
        message["From"]    = SENDER_EMAIL
        message["To"]      = RECEIVER_EMAIL

        body = build_email_body(critical_events)
        message.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, message.as_string())

        print(f"[NOTIFIER] Alert email sent to {RECEIVER_EMAIL}")
        return True

    except smtplib.SMTPAuthenticationError:
        print("[NOTIFIER] Email failed: Authentication error. Check your email and app password.")
        return False

    except smtplib.SMTPException as e:
        print(f"[NOTIFIER] Email failed: {e}")
        return False

    except Exception as e:
        print(f"[NOTIFIER] Unexpected error: {e}")
        return False


def check_and_notify(triaged_events):
    """
    Looks through triaged events for any CRITICAL ones.
    If found, triggers the email alert.
    This function is called from app.py after processing logs.
    """
    critical_events = [
        event for event in triaged_events
        if event.get("severity") == "CRITICAL"
    ]

    if critical_events:
        print(f"[NOTIFIER] {len(critical_events)} CRITICAL events found.")
        send_alert_email(critical_events)
    else:
        print("[NOTIFIER] No critical events found. No alert sent.")

    return critical_events


if __name__ == "__main__":
    print("=== Testing Notifier ===\n")

    test_events = [
        {
            "event_type": "WEB_PATH_TRAVERSAL",
            "source_ip": "45.33.32.156",
            "score": 100,
            "severity": "CRITICAL",
            "timestamp": "Jan 10 08:21:31",
            "log_source": "apache_access.log",
            "raw_log": "GET /../../../etc/shadow HTTP/1.1"
        },
        {
            "event_type": "FIREWALL_BLOCK_SENSITIVE_PORT",
            "source_ip": "45.33.32.156",
            "score": 90,
            "severity": "CRITICAL",
            "timestamp": "Jan 10 08:20:01",
            "log_source": "firewall.log",
            "raw_log": "[UFW BLOCK] SRC=45.33.32.156 DPT=22"
        }
    ]

    print("=== Email Body Preview ===")
    body = build_email_body(test_events)
    print(body)

    print("\n=== Testing check_and_notify ===")
    check_and_notify(test_events)