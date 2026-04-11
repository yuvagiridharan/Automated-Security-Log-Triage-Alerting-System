# test_integration.py
# Author: Adith
# Purpose: Integration tests along with the full pipeline together

import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import db_manager
from log_parser import parse_log_file
from triage_engine import triage_all_events, get_summary

db_manager.DB_PATH = "test_integration.db"


class TestIntegration(unittest.TestCase):
    """
    Integration tests check that multiple components work together correctly.
    Unlike unit tests which test one function at a time,
    integration tests test the full flow from start to finish.
    """

    def setUp(self):
        """Runs before every test - sets up a clean database."""
        db_manager.create_tables()
        db_manager.clear_alerts()

    def tearDown(self):
        """Runs after every test - removes the test database."""
        if os.path.exists("test_integration.db"):
            os.remove("test_integration.db")

    def test_full_ssh_pipeline(self):
        """
        Integration test: Parse SSH log -> Triage -> Store in DB -> Retrieve
        Tests the complete flow for SSH logs.
        """
        events = parse_log_file("sample_logs/auth.log", "ssh")

        self.assertGreater(len(events), 0)

        triaged = triage_all_events(events)

        for event in triaged:
            self.assertIn("severity", event)
            self.assertIn("score", event)
            self.assertIn(event["severity"], ["LOW", "MEDIUM", "HIGH", "CRITICAL"])

        for event in triaged:
            db_manager.insert_alert(
                timestamp=event.get("timestamp", "unknown"),
                source_ip=event.get("source_ip", "unknown"),
                event_type=event.get("event_type", "UNKNOWN"),
                severity=event.get("severity", "LOW"),
                score=event.get("score", 0),
                raw_log=event.get("raw_log", ""),
                log_source=event.get("log_source", "unknown")
            )

        alerts = db_manager.get_all_alerts()
        self.assertEqual(len(alerts), len(triaged))

    def test_full_firewall_pipeline(self):
        """
        Integration test: Parse firewall log -> Triage -> Store -> Retrieve
        """
        events = parse_log_file("sample_logs/firewall.log", "firewall")
        self.assertGreater(len(events), 0)

        triaged = triage_all_events(events)

        for event in triaged:
            db_manager.insert_alert(
                timestamp=event.get("timestamp", "unknown"),
                source_ip=event.get("source_ip", "unknown"),
                event_type=event.get("event_type", "UNKNOWN"),
                severity=event.get("severity", "LOW"),
                score=event.get("score", 0),
                raw_log=event.get("raw_log", ""),
                log_source=event.get("log_source", "unknown")
            )

        alerts = db_manager.get_all_alerts()
        self.assertEqual(len(alerts), len(triaged))

    def test_critical_events_are_blacklisted(self):
        """
        Integration test: Checks that CRITICAL events auto-blacklist their source IP.
        """
        events = parse_log_file("sample_logs/apache_access.log", "apache")
        triaged = triage_all_events(events)

        for event in triaged:
            db_manager.insert_alert(
                timestamp=event.get("timestamp", "unknown"),
                source_ip=event.get("source_ip", "unknown"),
                event_type=event.get("event_type", "UNKNOWN"),
                severity=event.get("severity", "LOW"),
                score=event.get("score", 0),
                raw_log=event.get("raw_log", ""),
                log_source=event.get("log_source", "unknown")
            )
            if event.get("severity") == "CRITICAL":
                db_manager.blacklist_ip(
                    event.get("source_ip", "unknown"),
                    f"Auto-blacklisted: {event.get('event_type')}"
                )

        blacklist = db_manager.get_blacklisted_ips()
        self.assertGreater(len(blacklist), 0)

    def test_severity_summary_is_accurate(self):
        """
        Integration test: Checks that the summary counts match actual data.
        """
        events = parse_log_file("sample_logs/auth.log", "ssh")
        triaged = triage_all_events(events)

        summary = get_summary(triaged)

        self.assertEqual(
            summary["total"],
            summary["CRITICAL"] + summary["HIGH"] + summary["MEDIUM"] + summary["LOW"]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)