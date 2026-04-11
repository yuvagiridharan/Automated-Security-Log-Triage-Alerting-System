# app.py
# Author: Yuva
# Purpose: Main Flask web application 
# Acts as the backend API server for the dashboard
import os
from notifier import check_and_notify
from flask import Flask, jsonify, request, render_template
from log_parser import parse_log_file
from triage_engine import triage_all_events, get_summary
from db_manager import (
    create_tables,
    insert_alert,
    get_all_alerts,
    get_severity_counts,
    get_top_ips,
    blacklist_ip,
    get_blacklisted_ips,
    clear_alerts
)
import os

# APP SETUP

app = Flask(__name__)

app.config["SECRET_KEY"] = "securelogtriage2024"

UPLOAD_FOLDER = "sample_logs"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {"log", "txt"}



def allowed_file(filename):
    """
    Checks if an uploaded file has an allowed extension.
    Prevents users from uploading dangerous file types.
    """
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def process_and_store_logs(filepath, log_type):
    """
    Full pipeline for one log file:
    1. Parse the file into events
    2. Run triage on all events
    3. Save each event to the database
    4. Auto-blacklist any CRITICAL IPs
    Returns the list of triaged events.
    """
    events = parse_log_file(filepath, log_type)

    if not events:
        return []

    triaged = triage_all_events(events)

    for event in triaged:
        insert_alert(
            timestamp=event.get("timestamp", "unknown"),
            source_ip=event.get("source_ip", "unknown"),
            event_type=event.get("event_type", "UNKNOWN"),
            severity=event.get("severity", "LOW"),
            score=event.get("score", 0),
            raw_log=event.get("raw_log", ""),
            log_source=event.get("log_source", "unknown")
        )

        if event.get("severity") == "CRITICAL":
            blacklist_ip(
                event.get("source_ip", "unknown"),
                f"Auto-blacklisted: {event.get('event_type')}"
            )

    
    check_and_notify(triaged)

    return triaged



@app.route("/")
def index():
    """
    Serves the main dashboard HTML page.
    This is what the user sees when they open the app in a browser.
    """
    return render_template("index.html")


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    """
    API endpoint that returns all alerts as JSON.
    The frontend JavaScript calls this to populate the alert table.
    Optional query parameter: ?severity=CRITICAL
    """
    severity = request.args.get("severity")

    if severity:
        from db_manager import get_alerts_by_severity
        alerts = get_alerts_by_severity(severity.upper())
    else:
        alerts = get_all_alerts(limit=100)

    return jsonify({
        "status": "success",
        "count": len(alerts),
        "alerts": alerts
    })


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """
    API endpoint that returns summary statistics as JSON.
    Used by the dashboard to draw the pie chart and bar chart.
    """
    severity_counts = get_severity_counts()
    top_ips = get_top_ips(limit=10)
    all_alerts = get_all_alerts(limit=1000)

    return jsonify({
        "status": "success",
        "severity_counts": severity_counts,
        "top_ips": top_ips,
        "total_alerts": len(all_alerts)
    })


@app.route("/api/blacklist", methods=["GET"])
def get_blacklist():
    """
    API endpoint that returns all blacklisted IPs as JSON.
    Displayed in the blacklist section of the dashboard.
    """
    ips = get_blacklisted_ips()
    return jsonify({
        "status": "success",
        "count": len(ips),
        "blacklisted_ips": ips
    })


@app.route("/api/process", methods=["POST"])
def process_logs():
    """
    API endpoint that triggers processing of the default sample log files.
    Called when the user clicks 'Run Analysis' on the dashboard.
    Clears old alerts first, then processes all three sample log files.
    """
    clear_alerts()

    results = {}

    log_files = [
        ("sample_logs/auth.log", "ssh"),
        ("sample_logs/firewall.log", "firewall"),
        ("sample_logs/apache_access.log", "apache"),
    ]

    total_events = 0

    for filepath, log_type in log_files:
        if os.path.exists(filepath):
            triaged = process_and_store_logs(filepath, log_type)
            results[log_type] = len(triaged)
            total_events += len(triaged)
        else:
            results[log_type] = 0

    all_alerts = get_all_alerts(limit=1000)
    severity_counts = get_severity_counts()

    return jsonify({
        "status": "success",
        "message": f"Processed {total_events} events",
        "breakdown": results,
        "severity_counts": severity_counts
    })


@app.route("/api/upload", methods=["POST"])
def upload_log():
    """
    API endpoint that accepts a custom log file upload from the user.
    The user picks the file and log type from the dashboard.
    """
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file provided"}), 400

    file = request.files["file"]
    log_type = request.form.get("log_type", "ssh")

    if file.filename == "":
        return jsonify({"status": "error", "message": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({"status": "error", "message": "Only .log and .txt files allowed"}), 400

    filename = file.filename
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(save_path)

    triaged = process_and_store_logs(save_path, log_type)

    return jsonify({
        "status": "success",
        "message": f"Processed {len(triaged)} events from {filename}",
        "events_found": len(triaged)
    })


@app.route("/api/clear", methods=["POST"])
def clear():
    """
    API endpoint to clear all alerts from the database.
    Used by the Reset button on the dashboard.
    """
    clear_alerts()
    return jsonify({
        "status": "success",
        "message": "All alerts cleared"
    })


# RUN THE APP

if __name__ == "__main__":
    create_tables()
    print("[APP] Security Log Triage System starting...")
    print("[APP] Open your browser and go to: http://127.0.0.1:5000")


    app.run(debug=True, port=5001)