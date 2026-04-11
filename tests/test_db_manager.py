# test_db_manager.py
# Author: Adith (copied for integration)
# Purpose: Unit tests for the database manager

import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import db_manager

db_manager.DB_PATH = "test_security_logs.db"


class TestDBManager(unittest.TestCase):
    """
    Test class for db_manager.py
    Each method starting with 'test_' is run automatically by unittest
    """

    def setUp(self):
        """
        setUp runs before every single test.
        Creates fresh tables and clears any old data.
        """
        db_manager.create_tables()
        db_manager.clear_alerts()

    def tearDown(self):
        """
        tearDown runs after every single test.
        Deletes the test database file so tests don't affect each other.
        """
        if os.path.exists("test_security_logs.db"):
            os.remove("test_security_logs.db")

    def test_create_tables(self):
        """
        Test that create_tables() runs without errors.
        If it raises an exception the test will fail automatically.
        """
        db_manager.create_tables()
        self.assertTrue(True)

    def test_insert_alert(self):
        """
        Test that we can insert an alert and retrieve it back.
        """
        db_manager.insert_alert(
            timestamp="Jan 10 08:23:11",
            source_ip="192.168.1.105",
            event_type="SSH_FAILED_LOGIN",
            severity="MEDIUM",
            score=30,
            raw_log="Failed password for root from 192.168.1.105",
            log_source="auth.log"
        )

        alerts = db_manager.get_all_alerts()

        self.assertEqual(len(alerts), 1)

        self.assertEqual(alerts[0]["source_ip"], "192.168.1.105")
        self.assertEqual(alerts[0]["event_type"], "SSH_FAILED_LOGIN")
        self.assertEqual(alerts[0]["severity"], "MEDIUM")

    def test_get_all_alerts_empty(self):
        """
        Test that get_all_alerts returns an empty list when no alerts exist.
        """
        alerts = db_manager.get_all_alerts()
        self.assertEqual(alerts, [])

    def test_get_severity_counts(self):
        """
        Test that severity counts are calculated correctly.
        """
        db_manager.insert_alert("ts1", "1.1.1.1", "SSH_FAILED_LOGIN",
                                 "MEDIUM", 30, "raw1", "auth.log")
        db_manager.insert_alert("ts2", "2.2.2.2", "WEB_PATH_TRAVERSAL",
                                 "CRITICAL", 90, "raw2", "apache.log")

        counts = db_manager.get_severity_counts()

        self.assertEqual(counts.get("MEDIUM"), 1)
        self.assertEqual(counts.get("CRITICAL"), 1)

    def test_get_top_ips(self):
        """
        Test that top IPs are returned in descending order of count.
        """
        for i in range(3):
            db_manager.insert_alert(f"ts{i}", "10.0.0.1", "SSH_FAILED_LOGIN",
                                     "MEDIUM", 30, f"raw{i}", "auth.log")

        db_manager.insert_alert("ts4", "10.0.0.2", "SSH_FAILED_LOGIN",
                                 "MEDIUM", 30, "raw4", "auth.log")

        top_ips = db_manager.get_top_ips(limit=10)

        self.assertEqual(top_ips[0]["source_ip"], "10.0.0.1")
        self.assertEqual(top_ips[0]["count"], 3)

    def test_blacklist_ip(self):
        """
        Test that an IP can be added to the blacklist.
        """
        db_manager.blacklist_ip("45.33.32.156", "Auto-blacklisted: WEB_PATH_TRAVERSAL")
        blacklist = db_manager.get_blacklisted_ips()

        self.assertEqual(len(blacklist), 1)
        self.assertEqual(blacklist[0]["ip_address"], "45.33.32.156")

    def test_blacklist_no_duplicates(self):
        """
        Test that the same IP cannot be blacklisted twice.
        INSERT OR IGNORE should prevent duplicates.
        """
        db_manager.blacklist_ip("45.33.32.156", "Reason 1")
        db_manager.blacklist_ip("45.33.32.156", "Reason 2")

        blacklist = db_manager.get_blacklisted_ips()

        self.assertEqual(len(blacklist), 1)

    def test_clear_alerts(self):
        """
        Test that clear_alerts() removes all records from the table.
        """
        db_manager.insert_alert("ts1", "1.1.1.1", "SSH_FAILED_LOGIN",
                                 "MEDIUM", 30, "raw1", "auth.log")
        db_manager.clear_alerts()

        alerts = db_manager.get_all_alerts()
        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)