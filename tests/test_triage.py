# test_triage.py
# Author: Yuva
# Purpose: Unit tests for the triage engine

import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from triage_engine import (
    get_base_score,
    get_severity_label,
    apply_ip_bonus,
    triage_event,
    triage_all_events,
    get_summary
)


class TestTriageEngine(unittest.TestCase):
    """
    Unit tests for triage_engine.py
    Each test checks one specific function in isolation.
    """

    def test_base_score_known_event(self):
        """
        Test that known event types return the correct base score.
        """
        self.assertEqual(get_base_score("SSH_FAILED_LOGIN"), 30)
        self.assertEqual(get_base_score("WEB_PATH_TRAVERSAL"), 80)
        self.assertEqual(get_base_score("FIREWALL_BLOCK_SENSITIVE_PORT"), 60)

    def test_base_score_unknown_event(self):
        """
        Test that unknown event types return default score of 5.
        """
        self.assertEqual(get_base_score("TOTALLY_UNKNOWN_EVENT"), 5)

    def test_severity_label_critical(self):
        """
        Test that scores 80 and above return CRITICAL.
        """
        self.assertEqual(get_severity_label(80), "CRITICAL")
        self.assertEqual(get_severity_label(100), "CRITICAL")
        self.assertEqual(get_severity_label(95), "CRITICAL")

    def test_severity_label_high(self):
        """
        Test that scores 60-79 return HIGH.
        """
        self.assertEqual(get_severity_label(60), "HIGH")
        self.assertEqual(get_severity_label(75), "HIGH")

    def test_severity_label_medium(self):
        """
        Test that scores 30-59 return MEDIUM.
        """
        self.assertEqual(get_severity_label(30), "MEDIUM")
        self.assertEqual(get_severity_label(50), "MEDIUM")

    def test_severity_label_low(self):
        """
        Test that scores below 30 return LOW.
        """
        self.assertEqual(get_severity_label(0), "LOW")
        self.assertEqual(get_severity_label(29), "LOW")

    def test_ip_bonus_known_malicious(self):
        """
        Test that known malicious IPs get a score boost.
        """
        score = apply_ip_bonus(30, "45.33.32.156")
        self.assertEqual(score, 60)

    def test_ip_bonus_clean_ip(self):
        """
        Test that clean IPs get no score boost.
        """
        score = apply_ip_bonus(30, "192.168.1.1")
        self.assertEqual(score, 30)

    def test_triage_event_adds_score_and_severity(self):
        """
        Test that triage_event adds score and severity to the event dict.
        """
        event = {
            "event_type": "SSH_FAILED_LOGIN",
            "source_ip": "192.168.1.105",
            "timestamp": "Jan 10 08:23:11",
            "raw_log": "Failed password for root",
            "log_source": "auth.log"
        }

        result = triage_event(event, [event])

        self.assertIn("score", result)
        self.assertIn("severity", result)
        self.assertIsInstance(result["score"], int)
        self.assertIn(result["severity"], ["LOW", "MEDIUM", "HIGH", "CRITICAL"])

    def test_score_capped_at_100(self):
        """
        Test that score never exceeds 100 even for very dangerous events.
        """
        event = {
            "event_type": "WEB_PATH_TRAVERSAL",
            "source_ip": "45.33.32.156",
            "timestamp": "ts",
            "raw_log": "raw",
            "log_source": "apache.log"
        }

        result = triage_event(event, [event])
        self.assertLessEqual(result["score"], 100)

    def test_get_summary_totals(self):
        """
        Test that summary counts add up to total correctly.
        """
        events = [
            {"severity": "CRITICAL", "score": 90},
            {"severity": "HIGH",     "score": 70},
            {"severity": "MEDIUM",   "score": 40},
            {"severity": "LOW",      "score": 10},
        ]

        summary = get_summary(events)

        self.assertEqual(summary["total"], 4)
        self.assertEqual(summary["CRITICAL"], 1)
        self.assertEqual(summary["HIGH"], 1)
        self.assertEqual(summary["MEDIUM"], 1)
        self.assertEqual(summary["LOW"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)