# SIEM-in-Python

# Python SIEM

Educational **Security Information and Event Management (SIEM)** developed in Python for collecting, processing, storing, correlating and detecting security events.

The project was designed as a practical cybersecurity laboratory, focusing on the fundamental concepts behind SIEM platforms.

## Features

* Log ingestion
* Event parsing
* Event normalization
* SQLite database
* Security event storage
* Temporal event correlation
* SSH brute-force detection
* Port-scan detection
* Suspicious-login detection
* Security alert generation
* Alert severity classification
* CLI interface
* Real-time log monitoring
* Demo log generation
* Event and alert searching
* Terminal dashboard

## Architecture

```text
                    LOG SOURCES
                         │
                         ▼
                  ┌─────────────┐
                  │   Collector │
                  └──────┬──────┘
                         │
                         ▼
                  ┌─────────────┐
                  │    Parser   │
                  └──────┬──────┘
                         │
                         ▼
                  ┌─────────────┐
                  │ Normalizer  │
                  └──────┬──────┘
                         │
                         ▼
                  ┌─────────────┐
                  │   SQLite    │
                  └──────┬──────┘
                         │
                         ▼
               ┌──────────────────┐
               │ Detection Engine │
               └────────┬─────────┘
                        │
                 ┌──────┴──────┐
                 ▼             ▼
              Rules       Correlation
                 │             │
                 └──────┬──────┘
                        ▼
                   ┌─────────┐
                   │ Alerts  │
                   └─────────┘
```

## Detection Rules

### SSH Brute Force

The SIEM tracks failed SSH authentication attempts by source IP.

An alert is generated when:

```text
5 or more failed authentication attempts
from the same IP within 60 seconds
```

Example:

```text
Failed password for admin from 192.168.1.50
```

Detection:

```text
[ALERT] HIGH
Rule: SSH_BRUTE_FORCE
Source IP: 192.168.1.50
```

### Port Scan

The system can identify port-scan events represented in the log source.

Example:

```text
PORT_SCAN src=10.0.0.55 ports=21,22,23,25,53,80,443
```

The SIEM generates:

```text
[ALERT] HIGH
Rule: PORT_SCAN
Source IP: 10.0.0.55
```

### Suspicious Login

The system also supports explicit suspicious-login events.

Example:

```text
SUSPICIOUS_LOGIN user=root src=172.16.0.99
```

Result:

```text
[ALERT] HIGH
Rule: SUSPICIOUS_LOGIN
User: root
Source IP: 172.16.0.99
```

## Requirements

* Python 3.9+
* SQLite3

No external Python dependencies are required for the current version.

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/python-siem.git
cd python-siem
```

Run the help menu:

```bash
python3 siem.py --help
```

## Quick Start

Generate demonstration logs:

```bash
python3 siem.py demo
```

Process the demonstration logs:

```bash
python3 siem.py ingest security.log
```

Or generate and process everything automatically:

```bash
python3 siem.py run-demo
```

## Dashboard

View SIEM statistics:

```bash
python3 siem.py dashboard
```

Example:

```text
============================================================
                    PYTHON SIEM
============================================================

Events processed : 8
Alerts generated : 3

Alerts by severity:
  LOW      : 0
  MEDIUM   : 0
  HIGH     : 3
  CRITICAL : 0
============================================================
```

## Viewing Events

Display recent events:

```bash
python3 siem.py events
```

Search for a specific IP:

```bash
python3 siem.py events --query 192.168.1.50
```

Limit the number of results:

```bash
python3 siem.py events --limit 10
```

## Viewing Alerts

Display generated security alerts:

```bash
python3 siem.py alerts
```

## Real-Time Monitoring

The SIEM can monitor a log file continuously.

Start monitoring:

```bash
python3 siem.py watch security.log
```

Then, from another terminal, append an event:

```bash
echo "Failed password for admin from 192.168.1.99" >> security.log
```

After enough failed authentication attempts, the SIEM will generate a brute-force alert.

## Database

The system automatically creates:

```text
siem.db
```

The database contains two primary tables:

### events

Stores normalized security events.

Relevant fields include:

* timestamp
* source
* event type
* username
* source IP
* destination IP
* destination port
* action
* severity
* raw log

### alerts

Stores detected security incidents.

Relevant fields include:

* timestamp
* detection rule
* severity
* source IP
* username
* message
* related event ID

## Example Event

```json
{
    "timestamp": "2026-08-15T09:20:31",
    "source": "ssh",
    "event_type": "authentication_failure",
    "username": "admin",
    "src_ip": "192.168.1.50",
    "severity": "medium"
}
```

## Example Alert

```text
Rule: SSH_BRUTE_FORCE
Severity: HIGH
Source IP: 192.168.1.50
Message: Possible SSH brute force detected from
192.168.1.50: 5 failed attempts within 60 seconds.
```

## Project Structure

The current prototype is intentionally implemented in a single Python file:

```text
python-siem/
├── siem.py
├── security.log
└── siem.db
```

Future versions will separate the system into independent modules:

```text
python-siem/
├── collector/
├── parser/
├── detector/
├── correlation/
├── database/
├── rules/
├── api/
├── dashboard/
├── tests/
└── siem.py
```

## Technologies

* Python
* SQLite
* Regular Expressions
* Event Correlation
* Log Analysis
* Security Detection Rules
* Command-Line Interface

## Cybersecurity Concepts

This project provides practical exposure to:

* SIEM architecture
* Security event management
* Log collection
* Log parsing
* Event normalization
* Detection engineering
* Correlation rules
* Authentication monitoring
* Brute-force detection
* Network reconnaissance detection
* Alert management
* Security monitoring

## Roadmap

Planned improvements:

* [ ] Modular architecture
* [ ] YAML-based detection rules
* [ ] REST API with FastAPI
* [ ] Web dashboard
* [ ] Syslog ingestion
* [ ] Windows Event Log ingestion
* [ ] Linux authentication log ingestion
* [ ] More correlation rules
* [ ] MITRE ATT&CK mapping
* [ ] Alert deduplication
* [ ] IP reputation integration
* [ ] Authentication and authorization
* [ ] Unit and integration tests
* [ ] Docker support
* [ ] Elasticsearch/OpenSearch integration

## Security Notice

This project is intended for **educational and authorized security testing purposes**.

The detection examples are intentionally simplified and should not be considered production-grade security detection mechanisms.

Only monitor systems and logs for which you have authorization.

## Author

**Cauet Mendes Franca de Aguiar**

Computer Engineering student at Universidade Federal de Sergipe with an interest in cybersecurity, penetration testing, bug bounty and security research.

## License

This project is released under the MIT License.
