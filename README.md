# Automated Security Log Triage & Alerting System

> A Python-based security operations tool that ingests raw system logs, classifies events by threat type, scores them using a multi-factor triage engine, persists alerts to a database, and surfaces findings through a live web dashboard with automatic IP blacklisting.

---

## Table of Contents

- [Overview](#overview)
- [Motivation & Problem Statement](#motivation--problem-statement)
- [System Architecture](#system-architecture)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Module Breakdown](#module-breakdown)
  - [log_parser.py](#log_parserpy)
  - [triage_engine.py](#triage_enginepy)
  - [db_manager.py](#db_managerpy)
  - [notifier.py](#notifierpy)
  - [security_config.py](#security_configpy)
  - [app.py](#apppy)
- [Severity Scoring Model](#severity-scoring-model)
- [REST API Reference](#rest-api-reference)
- [Getting Started](#getting-started)
- [Running the Tests](#running-the-tests)
- [Sample Log Formats](#sample-log-formats)
- [Security Considerations](#security-considerations)
- [Academic Context](#academic-context)
- [Author](#author)

---

## Overview

Modern infrastructure generates thousands of log lines per hour across SSH daemons, firewall engines, and web servers. Security analysts face the challenge of distinguishing genuine threats from routine noise without manual inspection of every event. This project implements a lightweight **Security Information and Event Management (SIEM)-inspired pipeline** that automates the three core stages of that process: **parsing**, **triage**, and **alerting**.

The system accepts raw log files in standard Linux formats (`auth.log`, UFW firewall logs, Apache Combined Log Format), classifies each line into a structured security event, scores it using a weighted multi-factor model, stores it in a persistent SQLite database, and presents the aggregated findings on a real-time Flask web dashboard. Any event scored as CRITICAL triggers an automatic IP blacklisting action and a configurable notification.

---

## Motivation & Problem Statement

Security event triage is one of the most resource-intensive tasks in a Security Operations Centre (SOC). According to the 2023 IBM Cost of a Data Breach Report, the mean time to identify a breach remains over 200 days — a figure directly tied to the volume and unstructured nature of log data that analysts must process.

Manual log review introduces three compounding problems. First, alert fatigue: analysts exposed to high volumes of low-severity events begin to under-prioritise genuinely dangerous signals. Second, inconsistency: different analysts apply different thresholds to the same event types, producing non-reproducible triage outcomes. Third, latency: manual workflows cannot match the speed at which brute-force attacks, path traversal attempts, or port scans escalate.

This project addresses all three by encoding triage logic into a deterministic scoring engine, persisting decisions to a queryable store, and surfacing findings through a filterable dashboard — reducing the analyst's cognitive load to reviewing pre-ranked, colour-coded alerts rather than raw log text.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     INPUT LAYER                         │
│   auth.log   │   firewall.log   │   apache_access.log   │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│                  log_parser.py                          │
│  Regex-based extraction → structured event dictionaries │
│  Supported: SSH / UFW Firewall / Apache HTTP            │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│               triage_engine.py                          │
│  Base score (event type) + IP threat intel bonus        │
│  + Repeat-IP brute force penalty → severity label       │
│  Levels: LOW │ MEDIUM │ HIGH │ CRITICAL                 │
└──────────────┬────────────────────────┬─────────────────┘
               │                        │
               ▼                        ▼
┌──────────────────────┐   ┌────────────────────────────┐
│    db_manager.py     │   │       notifier.py           │
│  SQLite persistence  │   │  Threshold-based alerting   │
│  Alerts + Blacklist  │   │  for CRITICAL events        │
└──────────┬───────────┘   └────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────┐
│                    app.py (Flask)                       │
│   REST API endpoints + Jinja2 dashboard template        │
│   /api/alerts  /api/stats  /api/blacklist  /api/upload  │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│             templates/index.html + static/              │
│   Live dashboard: severity chart, alert table,          │
│   top IPs, blacklist view, file upload                  │
└─────────────────────────────────────────────────────────┘
```

---

## Features

- **Multi-source log parsing** — handles three distinct Linux log formats: OpenSSH `auth.log`, UFW kernel firewall logs, and Apache Combined Log Format, each with dedicated regex parsers and event classifiers.

- **Deterministic triage scoring** — every parsed event is assigned a numeric score (0–100) based on its event type, source IP reputation, and frequency of occurrence. Scores map to four severity levels: LOW, MEDIUM, HIGH, and CRITICAL.

- **Threat intelligence integration** — a configurable list of known-malicious IP addresses applies a score boost to any event originating from those addresses, simulating real-world threat feed enrichment.

- **Brute-force detection** — the triage engine counts per-IP event frequency across the current analysis window and applies escalating penalties for repeated offenders, surfacing credential-stuffing and brute-force patterns automatically.

- **Automatic IP blacklisting** — any event reaching CRITICAL severity triggers an automatic blacklisting record in the database, with the event type recorded as the reason. Blacklisted IPs are viewable on the dashboard.

- **Persistent alert storage** — all triaged events are written to a SQLite database via `db_manager.py`, enabling historical querying, severity filtering, and statistical aggregation without reprocessing log files.

- **RESTful API backend** — Flask exposes six JSON endpoints covering alert retrieval, statistics, blacklist management, log processing, file upload, and database reset.

- **Live web dashboard** — a single-page HTML dashboard queries the API and displays a severity breakdown chart, a filterable alert table, top offending IPs, and the current blacklist. Custom log files can be uploaded and analysed directly from the browser.

- **Configurable notification system** — `notifier.py` implements a threshold-based alerting mechanism that fires when CRITICAL events are detected during a processing run.

- **Unit test suite** — the `tests/` directory provides test coverage for parsing, triage logic, and database operations using `pytest`.

---

## Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| Language | Python 3.x | Core application logic |
| Web framework | Flask 3.1 | REST API and template rendering |
| Templating | Jinja2 3.1 | Server-side HTML rendering |
| Database | SQLite (via `sqlite3`) | Lightweight persistent event store |
| Log parsing | `re` (standard library) | Regex-based log line extraction |
| Date handling | `datetime` (standard library) | Timestamp normalisation |
| Testing | pytest 9.x | Unit and integration test runner |
| Frontend | HTML5, CSS3, JavaScript | Dashboard UI |
| Security utilities | Werkzeug 3.1, bleach 6.3 | Input sanitisation and file handling |

---

## Project Structure

```
Automated-Security-Log-Triage-Alerting-System/
│
├── app.py                  ← Flask application: routes, pipeline orchestration
├── log_parser.py           ← Regex parsers for SSH, firewall, and Apache logs
├── triage_engine.py        ← Scoring engine: event scores, IP bonuses, brute-force detection
├── db_manager.py           ← SQLite interface: alerts table, blacklist table, queries
├── notifier.py             ← Threshold-based alerting for CRITICAL events
├── security_config.py      ← Centralised configuration: thresholds, known-malicious IPs
├── requirements.txt        ← Pinned Python dependencies
│
├── sample_logs/
│   ├── auth.log            ← Sample SSH authentication log (OpenSSH format)
│   ├── firewall.log        ← Sample UFW kernel firewall log
│   └── apache_access.log   ← Sample Apache access log (Combined Log Format)
│
├── templates/
│   └── index.html          ← Jinja2 dashboard template
│
├── static/
│   ├── style.css           ← Dashboard stylesheet
│   └── dashboard.js        ← Frontend logic: API polling, chart rendering
│
└── tests/
    └── test_*.py           ← pytest unit tests for parser, triage, and db modules
```

---

## Module Breakdown

### log_parser.py

The parser module is responsible for transforming raw, unstructured log text into structured Python dictionaries that the triage engine can reason about. It defines four compiled regular expression patterns as module-level constants, ensuring they are compiled once at import time rather than on every call.

**Supported log formats and event classifications:**

| Log Source | Event Type | Trigger Condition |
|---|---|---|
| auth.log | `SSH_FAILED_LOGIN` | "Failed password" in message |
| auth.log | `SSH_SUCCESSFUL_LOGIN` | "Accepted password" or "Accepted publickey" |
| auth.log | `SSH_INVALID_USER` | "invalid user" in message |
| auth.log | `SUDO_COMMAND` | "sudo" in message |
| auth.log | `SSH_OTHER` | Any other sshd message |
| firewall.log | `FIREWALL_BLOCK_SENSITIVE_PORT` | UFW BLOCK on ports 22, 3389, 445, 8080, 3306, 23 |
| firewall.log | `FIREWALL_BLOCK` | UFW BLOCK on any other port |
| firewall.log | `FIREWALL_ALLOW` | UFW ALLOW action |
| apache_access.log | `WEB_UNAUTHORISED_ACCESS` | HTTP 401 or 403 response |
| apache_access.log | `WEB_PATH_TRAVERSAL` | Path contains `/etc/passwd`, `../`, `.env`, `/admin` |
| apache_access.log | `WEB_SERVER_ERROR` | HTTP 5xx response |
| apache_access.log | `WEB_POST_SUCCESS` | POST method with HTTP 200 |
| apache_access.log | `WEB_NORMAL` | All other requests |

Each parser function returns a dictionary containing: `timestamp`, `source_ip`, `event_type`, `raw_log`, and `log_source`. Apache events additionally carry `http_status` and `path`. Firewall events carry `port`. The top-level `parse_log_file()` function accepts a file path and log type string, opens the file, iterates line by line, and dispatches to the appropriate parser. Lines that do not match the expected pattern return `None` and are silently skipped, ensuring robustness against malformed or partial log entries.

---

### triage_engine.py

The triage engine is the analytical core of the system. It implements a three-factor additive scoring model that converts a parsed event dictionary into a numeric severity score and a human-readable severity label.

**Scoring factors:**

**1. Base score (event type weight)**

Each event type is mapped to a base score in the `EVENT_SCORES` dictionary. These scores encode the relative inherent risk of each event class:

```
WEB_PATH_TRAVERSAL          → 80  (CRITICAL baseline)
FIREWALL_BLOCK_SENSITIVE_PORT → 60  (HIGH baseline)
SUDO_COMMAND                → 50  (MEDIUM-HIGH)
SSH_INVALID_USER            → 40  (MEDIUM)
WEB_UNAUTHORISED_ACCESS     → 40  (MEDIUM)
SSH_FAILED_LOGIN            → 30  (MEDIUM)
FIREWALL_BLOCK              → 25  (LOW-MEDIUM)
WEB_SERVER_ERROR            → 20  (LOW)
SSH_SUCCESSFUL_LOGIN        → 10  (LOW)
WEB_POST_SUCCESS            → 10  (LOW)
FIREWALL_ALLOW /SSH_OTHER   →  5  (Informational)
```

**2. Threat intelligence bonus (+30)**

If the source IP of an event is present in the `KNOWN_MALICIOUS_IPS` list defined in the triage engine, a flat bonus of 30 points is added. This simulates integration with a real-world threat intelligence feed, where known-bad IPs (command and control servers, TOR exit nodes, repeat offenders from abuse databases) carry elevated risk regardless of the event type they generate.

**3. Repeat-IP brute-force penalty (+20 or +40)**

The engine counts how many times the same source IP appears across all events in the current analysis window. An IP appearing more than 5 times incurs a +20 penalty. An IP appearing more than 10 times incurs a +40 penalty. This directly models brute-force attack detection: a single failed SSH login may score MEDIUM, but the same IP generating 15 failed logins across the log file escalates to CRITICAL automatically.

**Severity thresholds:**

| Score Range | Severity |
|---|---|
| 80 – 100 | CRITICAL |
| 60 – 79 | HIGH |
| 30 – 59 | MEDIUM |
| 0 – 29 | LOW |

All scores are capped at 100. The `triage_all_events()` function processes a full list of events and returns them enriched with `score` and `severity` keys. The `get_summary()` function aggregates the results into a severity count dictionary used by the dashboard statistics API.

---

### db_manager.py

The database manager provides the persistence layer using Python's built-in `sqlite3` module. It exposes a functional interface — no ORM is used — keeping the data access layer simple, auditable, and dependency-free.

The module manages two tables:

**`alerts` table** — stores every triaged security event with columns for timestamp, source IP, event type, severity, score, raw log text, and log source filename.

**`blacklist` table** — stores IPs that have been automatically or manually flagged, with a reason string and a timestamp.

Key functions include `create_tables()` for schema initialisation, `insert_alert()` for writing a single triaged event, `get_all_alerts()` with an optional limit parameter, `get_alerts_by_severity()` for filtered retrieval, `get_severity_counts()` for aggregate statistics, `get_top_ips()` for ranking source IPs by event count, `blacklist_ip()` for recording a blacklist entry, `get_blacklisted_ips()` for retrieval, and `clear_alerts()` for resetting the database between analysis runs.

---

### notifier.py

The notifier implements the alerting layer of the pipeline. It is called at the end of each processing run with the full list of triaged events. Its `check_and_notify()` function filters for events at or above a configurable severity threshold and dispatches notifications accordingly.

In the current implementation, notifications are printed to the console, making the system suitable for development, testing, and demonstration environments. The architecture is designed for extension: replacing the print statements with SMTP calls, webhook POST requests (Slack, PagerDuty), or syslog writes requires changes only to this module, leaving the rest of the pipeline untouched.

---

### security_config.py

A centralised configuration module that externalises all tunable parameters from the business logic. This separation ensures that operational parameters — severity thresholds, known-malicious IP lists, notification settings, sensitive port definitions — can be modified without touching parser or engine code. This follows the principle of configuration-as-code and is the appropriate pattern for security tooling where thresholds may need rapid adjustment in response to a live incident.

---

### app.py

The Flask application serves as the integration layer, wiring together all modules into a functional web service. On startup, it calls `create_tables()` to ensure the database schema exists, then begins serving HTTP requests on port 5001.

The `process_and_store_logs()` function implements the complete end-to-end pipeline for a single log file: parse → triage → persist → auto-blacklist CRITICAL IPs → notify. This function is called both by the default sample-log processing endpoint and by the file upload endpoint, ensuring identical handling regardless of the log source.

File upload security is handled by validating file extensions against a whitelist (`{.log, .txt}`) before saving to the upload directory. Files with disallowed extensions are rejected with a 400 response.

---

## Severity Scoring Model

The following table illustrates how the three scoring factors combine for representative attack scenarios:

| Scenario | Base Score | TI Bonus | Brute-Force Penalty | Final Score | Severity |
|---|---|---|---|---|---|
| Single SSH failed login, unknown IP | 30 | 0 | 0 | 30 | MEDIUM |
| SSH failed login, known-malicious IP | 30 | +30 | 0 | 60 | HIGH |
| 15 SSH failed logins, same IP | 30 | 0 | +40 | 70 | HIGH |
| 15 SSH failed logins, known-malicious IP | 30 | +30 | +40 | 100 | CRITICAL |
| Web path traversal (`.env` probe) | 80 | 0 | 0 | 80 | CRITICAL |
| UFW block on port 3389 (RDP) | 60 | 0 | 0 | 60 | HIGH |
| Normal web request | 5 | 0 | 0 | 5 | LOW |

---

## REST API Reference

All endpoints return JSON. The base URL when running locally is `http://127.0.0.1:5001`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves the main dashboard HTML page |
| `GET` | `/api/alerts` | Returns all alerts. Optional query param: `?severity=CRITICAL` |
| `GET` | `/api/stats` | Returns severity counts, top 10 IPs, and total alert count |
| `GET` | `/api/blacklist` | Returns all blacklisted IPs with reasons and timestamps |
| `POST` | `/api/process` | Clears existing alerts and processes all three sample log files |
| `POST` | `/api/upload` | Accepts a multipart form upload: `file` (`.log`/`.txt`) + `log_type` (`ssh`/`firewall`/`apache`) |
| `POST` | `/api/clear` | Clears all alerts from the database |

**Example — GET /api/alerts response:**
```json
{
  "status": "success",
  "count": 47,
  "alerts": [
    {
      "id": 1,
      "timestamp": "Apr 12 03:22:14",
      "source_ip": "45.33.32.156",
      "event_type": "SSH_FAILED_LOGIN",
      "severity": "CRITICAL",
      "score": 100,
      "raw_log": "Apr 12 03:22:14 server sshd[1234]: Failed password for root from 45.33.32.156",
      "log_source": "auth.log"
    }
  ]
}
```

**Example — GET /api/stats response:**
```json
{
  "status": "success",
  "severity_counts": {"CRITICAL": 4, "HIGH": 11, "MEDIUM": 18, "LOW": 14},
  "top_ips": [
    {"source_ip": "45.33.32.156", "count": 23},
    {"source_ip": "198.51.100.77", "count": 9}
  ],
  "total_alerts": 47
}
```

---

## Getting Started

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Installation

```bash
# Clone the repository
git clone https://github.com/yuvagiridharan/Automated-Security-Log-Triage-Alerting-System.git
cd Automated-Security-Log-Triage-Alerting-System

# Install dependencies
pip install -r requirements.txt
```

### Running the application

```bash
python app.py
```

The application starts on `http://127.0.0.1:5001`. Open this URL in your browser to access the dashboard.

### Running the first analysis

1. Open the dashboard in your browser at `http://127.0.0.1:5001`
2. Click **Run Analysis** — this processes all three sample log files in the `sample_logs/` directory
3. The dashboard will populate with severity counts, the alert table, and top offending IPs
4. Use the severity filter to view only CRITICAL or HIGH events
5. Click **Blacklist** in the navigation to see IPs that were auto-blacklisted

### Uploading a custom log file

From the dashboard, use the **Upload Log** section to select a `.log` or `.txt` file from your local machine and specify the log type (`ssh`, `firewall`, or `apache`). The file is processed through the same pipeline as the sample logs and results are immediately visible on the dashboard.

---

## Running the Tests

The test suite uses pytest and covers the parsing, triage, and database modules.

```bash
# Run all tests
pytest tests/

# Run with verbose output
pytest tests/ -v

# Run a specific test file
pytest tests/test_log_parser.py -v
```

---

## Sample Log Formats

The parser expects the following standard Linux log formats. Custom log files must conform to these formats for correct parsing.

**auth.log (SSH — OpenSSH format):**
```
Apr 12 03:22:14 server sshd[1234]: Failed password for root from 192.168.1.100 port 54321 ssh2
Apr 12 03:25:01 server sshd[1235]: Accepted publickey for admin from 10.0.0.5 port 22 ssh2
Apr 12 03:26:44 server sshd[1236]: Invalid user guest from 203.0.113.45
```

**firewall.log (UFW kernel format):**
```
Apr 12 03:10:00 server kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.77 DST=10.0.0.1 DPT=22
Apr 12 03:11:30 server kernel: [UFW BLOCK] IN=eth0 SRC=45.33.32.156 DST=10.0.0.1 DPT=3389
Apr 12 03:12:00 server kernel: [UFW ALLOW] IN=eth0 SRC=10.0.0.5 DST=10.0.0.1 DPT=80
```

**apache_access.log (Apache Combined Log Format):**
```
192.168.1.200 - - [12/Apr/2024:03:15:00 +0000] "GET /index.html HTTP/1.1" 200
203.0.113.99 - - [12/Apr/2024:03:16:00 +0000] "GET /etc/passwd HTTP/1.1" 404
45.33.32.156 - - [12/Apr/2024:03:17:00 +0000] "POST /admin HTTP/1.1" 403
```

---

## Security Considerations

**Input validation** — file uploads are validated against an extension whitelist (`{.log, .txt}`) before being saved to disk. Filenames are not sanitised for path traversal; in a production deployment, `werkzeug.utils.secure_filename()` should be applied to all uploaded filenames before constructing the save path.

**Database** — SQLite is used as the persistence layer, which is appropriate for single-instance deployments and academic demonstration. A production deployment should migrate to PostgreSQL or MySQL with parameterised queries throughout. All current database interactions use parameterised queries to prevent SQL injection.

**Secret key** — the Flask `SECRET_KEY` is hardcoded in `app.py`. In any environment beyond local development, this should be loaded from an environment variable or secrets manager and must be cryptographically random.

**Threat intelligence list** — the `KNOWN_MALICIOUS_IPS` list in `triage_engine.py` is a static compile-time list for demonstration purposes. A production system should query a live threat intelligence API (e.g., AbuseIPDB, VirusTotal, or an internal TI platform) or load from an external file that can be updated without redeploying the application.

**No authentication** — the Flask dashboard and API have no authentication layer. In a production or shared environment, access should be restricted behind HTTP Basic Auth, OAuth, or a reverse proxy with IP allowlisting.

---

## Academic Context

This project was developed as part of the **MSc Cybersecurity** programme at **Dublin Business School**, Ireland. It demonstrates applied competency in the following areas aligned with the programme curriculum:

- **Security operations and incident response** — modelling the triage and prioritisation workflow of a Security Operations Centre
- **Network and system security** — parsing and interpreting real-world log formats from SSH, firewall, and web server components
- **Secure software development** — layered architecture with separation of concerns, input validation, and parameterised database queries
- **Threat intelligence** — simulating threat feed enrichment via known-malicious IP scoring
- **Python programming for security** — regex-based parsing, modular design, RESTful API development, and automated testing with pytest

---

## Author

**Yuvagiridharan**
MSc Cybersecurity — Dublin Business School, Dublin, Ireland
GitHub: [@yuvagiridharan](https://github.com/yuvagiridharan)

---

*This project is intended for educational and research purposes. The sample log files contain synthetic data only. Do not deploy in a production environment without addressing the security considerations noted above.*
