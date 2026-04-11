# db_manager.py
# Author: Adith (copied for integration)
# Purpose: Handles all database operations for the Security Log Triage System

import sqlite3
import os
from datetime import datetime

DB_PATH = "security_logs.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def create_tables():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            score INTEGER NOT NULL,
            raw_log TEXT NOT NULL,
            log_source TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blacklisted_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT,
            flagged_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS triage_summary (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            total_events INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            generated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
    print("[DB] Tables created successfully.")


def insert_alert(timestamp, source_ip, event_type, severity, score, raw_log, log_source):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts (timestamp, source_ip, event_type, severity, score, raw_log, log_source)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, source_ip, event_type, severity, score, raw_log, log_source))
    conn.commit()
    conn.close()


def get_all_alerts(limit=100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM alerts
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_alerts_by_severity(severity):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM alerts
        WHERE severity = ?
        ORDER BY created_at DESC
    """, (severity,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_severity_counts():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT severity, COUNT(*) as count
        FROM alerts
        GROUP BY severity
    """)
    rows = {row["severity"]: row["count"] for row in cursor.fetchall()}
    conn.close()
    return rows


def get_top_ips(limit=10):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT source_ip, COUNT(*) as count
        FROM alerts
        WHERE source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY count DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def blacklist_ip(ip_address, reason):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO blacklisted_ips (ip_address, reason)
        VALUES (?, ?)
    """, (ip_address, reason))
    conn.commit()
    conn.close()


def get_blacklisted_ips():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blacklisted_ips ORDER BY flagged_at DESC")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def clear_alerts():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()


if __name__ == "__main__":
    create_tables()
    print("[DB] Database initialised at:", DB_PATH)