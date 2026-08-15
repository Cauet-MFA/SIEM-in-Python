#!/usr/bin/env python3

import argparse
import json
import re
import sqlite3
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path


# ============================================================
# CONFIGURAÇÃO
# ============================================================

DATABASE = "siem.db"
DEFAULT_LOG = "security.log"


# ============================================================
# UTILITÁRIOS
# ============================================================

def now():
    return datetime.now().isoformat(timespec="seconds")


def parse_timestamp(value):
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return datetime.now()


# ============================================================
# DATABASE
# ============================================================

class Database:

    def __init__(self, path=DATABASE):
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.create_tables()

    def create_tables(self):
        cursor = self.connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT,
                event_type TEXT,
                username TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                action TEXT,
                severity TEXT,
                raw TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                src_ip TEXT,
                username TEXT,
                message TEXT,
                event_id INTEGER
            )
        """)

        self.connection.commit()

    def insert_event(self, event):

        cursor = self.connection.cursor()

        cursor.execute("""
            INSERT INTO events (
                timestamp,
                source,
                event_type,
                username,
                src_ip,
                dst_ip,
                dst_port,
                action,
                severity,
                raw
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.get("timestamp"),
            event.get("source"),
            event.get("event_type"),
            event.get("username"),
            event.get("src_ip"),
            event.get("dst_ip"),
            event.get("dst_port"),
            event.get("action"),
            event.get("severity"),
            event.get("raw")
        ))

        self.connection.commit()

        return cursor.lastrowid

    def insert_alert(self, alert):

        cursor = self.connection.cursor()

        cursor.execute("""
            INSERT INTO alerts (
                timestamp,
                rule,
                severity,
                src_ip,
                username,
                message,
                event_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            alert["timestamp"],
            alert["rule"],
            alert["severity"],
            alert.get("src_ip"),
            alert.get("username"),
            alert["message"],
            alert.get("event_id")
        ))

        self.connection.commit()

        return cursor.lastrowid

    def search_events(self, query=None, limit=20):

        cursor = self.connection.cursor()

        if query:
            pattern = f"%{query}%"

            cursor.execute("""
                SELECT *
                FROM events
                WHERE raw LIKE ?
                   OR src_ip LIKE ?
                   OR username LIKE ?
                   OR event_type LIKE ?
                ORDER BY id DESC
                LIMIT ?
            """, (
                pattern,
                pattern,
                pattern,
                pattern,
                limit
            ))

        else:

            cursor.execute("""
                SELECT *
                FROM events
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))

        return cursor.fetchall()

    def get_alerts(self, limit=20):

        cursor = self.connection.cursor()

        cursor.execute("""
            SELECT *
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))

        return cursor.fetchall()

    def statistics(self):

        cursor = self.connection.cursor()

        cursor.execute("SELECT COUNT(*) FROM events")
        events = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM alerts")
        alerts = cursor.fetchone()[0]

        cursor.execute("""
            SELECT severity, COUNT(*)
            FROM alerts
            GROUP BY severity
        """)

        severity = {
            row[0]: row[1]
            for row in cursor.fetchall()
        }

        return {
            "events": events,
            "alerts": alerts,
            "severity": severity
        }

    def close(self):
        self.connection.close()


# ============================================================
# PARSER
# ============================================================

class Parser:

    SSH_FAILURE = re.compile(
        r"Failed password for (?:invalid user )?(\S+) from ([0-9.]+)"
    )

    SSH_SUCCESS = re.compile(
        r"Accepted password for (\S+) from ([0-9.]+)"
    )

    PORT_SCAN = re.compile(
        r"PORT_SCAN src=([0-9.]+) ports=([0-9,]+)"
    )

    SUSPICIOUS_LOGIN = re.compile(
        r"SUSPICIOUS_LOGIN user=(\S+) src=([0-9.]+)"
    )

    def parse(self, line):

        line = line.strip()

        if not line:
            return None

        timestamp = now()

        match = self.SSH_FAILURE.search(line)

        if match:

            username = match.group(1)
            src_ip = match.group(2)

            return {
                "timestamp": timestamp,
                "source": "ssh",
                "event_type": "authentication_failure",
                "username": username,
                "src_ip": src_ip,
                "dst_ip": None,
                "dst_port": None,
                "action": "login_failed",
                "severity": "medium",
                "raw": line
            }

        match = self.SSH_SUCCESS.search(line)

        if match:

            username = match.group(1)
            src_ip = match.group(2)

            return {
                "timestamp": timestamp,
                "source": "ssh",
                "event_type": "authentication_success",
                "username": username,
                "src_ip": src_ip,
                "dst_ip": None,
                "dst_port": None,
                "action": "login_success",
                "severity": "low",
                "raw": line
            }

        match = self.PORT_SCAN.search(line)

        if match:

            src_ip = match.group(1)
            ports = match.group(2).split(",")

            return {
                "timestamp": timestamp,
                "source": "network",
                "event_type": "port_scan",
                "username": None,
                "src_ip": src_ip,
                "dst_ip": None,
                "dst_port": len(ports),
                "action": "scan",
                "severity": "high",
                "raw": line
            }

        match = self.SUSPICIOUS_LOGIN.search(line)

        if match:

            username = match.group(1)
            src_ip = match.group(2)

            return {
                "timestamp": timestamp,
                "source": "authentication",
                "event_type": "suspicious_login",
                "username": username,
                "src_ip": src_ip,
                "dst_ip": None,
                "dst_port": None,
                "action": "login",
                "severity": "high",
                "raw": line
            }

        # Evento genérico

        return {
            "timestamp": timestamp,
            "source": "unknown",
            "event_type": "generic",
            "username": None,
            "src_ip": None,
            "dst_ip": None,
            "dst_port": None,
            "action": None,
            "severity": "low",
            "raw": line
        }


# ============================================================
# NORMALIZER
# ============================================================

class Normalizer:

    def normalize(self, event):

        if not event:
            return None

        normalized = event.copy()

        if normalized.get("src_ip") == "-":
            normalized["src_ip"] = None

        if normalized.get("username") == "-":
            normalized["username"] = None

        if normalized.get("severity") not in {
            "low",
            "medium",
            "high",
            "critical"
        }:
            normalized["severity"] = "low"

        return normalized


# ============================================================
# DETECTOR
# ============================================================

class DetectionEngine:

    def __init__(self):

        self.failed_logins = defaultdict(deque)

        self.port_scans = defaultdict(deque)

        self.suspicious_logins = defaultdict(deque)

    def analyze(self, event, event_id):

        alerts = []

        timestamp = parse_timestamp(event["timestamp"])

        src_ip = event.get("src_ip")

        # ----------------------------------------------------
        # SSH BRUTE FORCE
        # ----------------------------------------------------

        if event["event_type"] == "authentication_failure":

            if src_ip:

                attempts = self.failed_logins[src_ip]

                attempts.append(timestamp)

                cutoff = timestamp - timedelta(seconds=60)

                while attempts and attempts[0] < cutoff:
                    attempts.popleft()

                if len(attempts) >= 5:

                    alerts.append({
                        "timestamp": event["timestamp"],
                        "rule": "SSH_BRUTE_FORCE",
                        "severity": "high",
                        "src_ip": src_ip,
                        "username": event.get("username"),
                        "message": (
                            f"Possible SSH brute force detected from "
                            f"{src_ip}: {len(attempts)} failed attempts "
                            f"within 60 seconds."
                        ),
                        "event_id": event_id
                    })

                    # Evita gerar centenas de alertas
                    attempts.clear()

        # ----------------------------------------------------
        # PORT SCAN
        # ----------------------------------------------------

        if event["event_type"] == "port_scan":

            if src_ip:

                scans = self.port_scans[src_ip]

                scans.append(timestamp)

                cutoff = timestamp - timedelta(seconds=60)

                while scans and scans[0] < cutoff:
                    scans.popleft()

                if len(scans) >= 1:

                    alerts.append({
                        "timestamp": event["timestamp"],
                        "rule": "PORT_SCAN",
                        "severity": "high",
                        "src_ip": src_ip,
                        "username": None,
                        "message": (
                            f"Port scan detected from {src_ip}."
                        ),
                        "event_id": event_id
                    })

                    scans.clear()

        # ----------------------------------------------------
        # LOGIN SUSPEITO
        # ----------------------------------------------------

        if event["event_type"] == "suspicious_login":

            alerts.append({
                "timestamp": event["timestamp"],
                "rule": "SUSPICIOUS_LOGIN",
                "severity": "high",
                "src_ip": src_ip,
                "username": event.get("username"),
                "message": (
                    f"Suspicious login detected for user "
                    f"{event.get('username')} from {src_ip}."
                ),
                "event_id": event_id
            })

        return alerts


# ============================================================
# SIEM CORE
# ============================================================

class SIEM:

    def __init__(self, database=DATABASE):

        self.database = Database(database)
        self.parser = Parser()
        self.normalizer = Normalizer()
        self.detector = DetectionEngine()

    def process_line(self, line):

        event = self.parser.parse(line)

        if not event:
            return

        event = self.normalizer.normalize(event)

        event_id = self.database.insert_event(event)

        alerts = self.detector.analyze(
            event,
            event_id
        )

        for alert in alerts:

            alert_id = self.database.insert_alert(alert)

            self.print_alert(
                alert_id,
                alert
            )

    @staticmethod
    def print_alert(alert_id, alert):

        severity = alert["severity"].upper()

        print()
        print("=" * 70)
        print(f"[ALERT #{alert_id}] {severity}")
        print(f"Rule:     {alert['rule']}")
        print(f"Source IP: {alert.get('src_ip')}")
        print(f"User:      {alert.get('username')}")
        print(f"Message:   {alert['message']}")
        print("=" * 70)
        print()

    def process_file(self, path):

        path = Path(path)

        if not path.exists():

            print(
                f"[ERROR] Log file does not exist: {path}"
            )

            return

        print(f"[+] Monitoring {path}")

        with path.open(
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            for line in file:

                self.process_line(line)

    def watch_file(self, path):

        path = Path(path)

        if not path.exists():

            path.touch()

        print(f"[+] SIEM monitoring: {path}")
        print("[+] Press Ctrl+C to stop.")

        with path.open(
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            file.seek(0, 2)

            try:

                while True:

                    line = file.readline()

                    if line:

                        self.process_line(line)

                    else:

                        time.sleep(0.5)

            except KeyboardInterrupt:

                print("\n[+] Monitoring stopped.")

    def close(self):

        self.database.close()


# ============================================================
# LOG GENERATOR
# ============================================================

def generate_demo_logs(path=DEFAULT_LOG):

    logs = [

        "Failed password for admin from 192.168.1.50",

        "Failed password for admin from 192.168.1.50",

        "Failed password for admin from 192.168.1.50",

        "Failed password for admin from 192.168.1.50",

        "Failed password for admin from 192.168.1.50",

        "Accepted password for cauet from 192.168.1.20",

        "PORT_SCAN src=10.0.0.55 ports=21,22,23,25,53,80,110,443",

        "SUSPICIOUS_LOGIN user=root src=172.16.0.99"
    ]

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as file:

        for line in logs:

            file.write(line + "\n")

    print(f"[+] Demo logs written to {path}")


# ============================================================
# DASHBOARD
# ============================================================

def dashboard(database):

    stats = database.statistics()

    print()
    print("=" * 60)
    print("                    PYTHON SIEM")
    print("=" * 60)

    print()
    print(f"Events processed : {stats['events']}")
    print(f"Alerts generated : {stats['alerts']}")

    print()
    print("Alerts by severity:")

    severity = stats["severity"]

    print(
        f"  LOW      : {severity.get('low', 0)}"
    )

    print(
        f"  MEDIUM   : {severity.get('medium', 0)}"
    )

    print(
        f"  HIGH     : {severity.get('high', 0)}"
    )

    print(
        f"  CRITICAL : {severity.get('critical', 0)}"
    )

    print()
    print("=" * 60)
    print()


# ============================================================
# EVENTOS
# ============================================================

def show_events(database, query=None, limit=20):

    events = database.search_events(
        query=query,
        limit=limit
    )

    if not events:

        print("[+] No events found.")
        return

    print()

    for event in events:

        print(
            f"[{event['id']}] "
            f"{event['timestamp']} "
            f"{event['event_type']} "
            f"IP={event['src_ip']} "
            f"USER={event['username']}"
        )

        print(
            f"    {event['raw']}"
        )

    print()


def show_alerts(database, limit=20):

    alerts = database.get_alerts(
        limit=limit
    )

    if not alerts:

        print("[+] No alerts found.")
        return

    print()

    for alert in alerts:

        print(
            f"[{alert['id']}] "
            f"{alert['timestamp']} "
            f"{alert['severity'].upper()} "
            f"{alert['rule']}"
        )

        print(
            f"    IP={alert['src_ip']} "
            f"USER={alert['username']}"
        )

        print(
            f"    {alert['message']}"
        )

        print()


# ============================================================
# CLI
# ============================================================

def build_parser():

    parser = argparse.ArgumentParser(
        description="Python SIEM"
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    # ingest

    ingest = subparsers.add_parser(
        "ingest",
        help="Process a log file"
    )

    ingest.add_argument(
        "file"
    )

    # watch

    watch = subparsers.add_parser(
        "watch",
        help="Monitor a log file continuously"
    )

    watch.add_argument(
        "file"
    )

    # events

    events = subparsers.add_parser(
        "events",
        help="Show events"
    )

    events.add_argument(
        "-q",
        "--query"
    )

    events.add_argument(
        "-n",
        "--limit",
        type=int,
        default=20
    )

    # alerts

    alerts = subparsers.add_parser(
        "alerts",
        help="Show alerts"
    )

    alerts.add_argument(
        "-n",
        "--limit",
        type=int,
        default=20
    )

    # dashboard

    subparsers.add_parser(
        "dashboard",
        help="Show SIEM dashboard"
    )

    # demo

    demo = subparsers.add_parser(
        "demo",
        help="Generate demo logs"
    )

    demo.add_argument(
        "-o",
        "--output",
        default=DEFAULT_LOG
    )

    # run-demo

    subparsers.add_parser(
        "run-demo",
        help="Generate and process demo logs"
    )

    return parser


# ============================================================
# MAIN
# ============================================================

def main():

    parser = build_parser()

    args = parser.parse_args()

    siem = SIEM()

    try:

        if args.command == "ingest":

            siem.process_file(
                args.file
            )

        elif args.command == "watch":

            siem.watch_file(
                args.file
            )

        elif args.command == "events":

            show_events(
                siem.database,
                query=args.query,
                limit=args.limit
            )

        elif args.command == "alerts":

            show_alerts(
                siem.database,
                limit=args.limit
            )

        elif args.command == "dashboard":

            dashboard(
                siem.database
            )

        elif args.command == "demo":

            generate_demo_logs(
                args.output
            )

        elif args.command == "run-demo":

            generate_demo_logs()

            print(
                "[+] Processing demo logs..."
            )

            siem.process_file(
                DEFAULT_LOG
            )

            dashboard(
                siem.database
            )

        else:

            parser.print_help()

    finally:

        siem.close()


if __name__ == "__main__":
    main()