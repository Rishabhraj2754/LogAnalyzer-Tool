#!/usr/bin/env python3
"""
LOG FILE ANALYZER - Security Tool
Author: Rishabh Raj
Purpose: Parse and analyze security log files to detect threats
Phase 2: Threat detection - brute force, enumeration, distributed attacks
"""

import os
from datetime import datetime

class LogAnalyzer:
    def __init__(self):
        self.log_file = None
        self.log_entries = []
        self.total_lines = 0

        # Phase 2: thresholds for threat detection
        # If an IP fails login this many times → it's an attack
        self.brute_force_threshold = 5
        self.critical_threshold = 10

    def load_log_file(self, filepath):
        """Read log file and store every line"""
        if not os.path.exists(filepath):
            print(f"ERROR: File not found: {filepath}")
            return False

        self.log_file = filepath

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                self.total_lines += 1
                self.log_entries.append(line)

        print(f"Loaded: {filepath}")
        print(f"Total lines read: {self.total_lines}")
        return True

    def parse_entry(self, line):
        """Break one log line into its parts"""
        entry = {
            'raw': line,
            'date': 'Unknown',
            'event_type': 'Unknown',
            'username': 'Unknown',
            'ip_address': 'Unknown',
        }

        parts = line.split()
        if len(parts) >= 3:
            entry['date'] = f"{parts[0]} {parts[1]} {parts[2]}"

        if 'Failed password' in line:
            entry['event_type'] = 'FAILED_LOGIN'
        elif 'Accepted password' in line:
            entry['event_type'] = 'SUCCESSFUL_LOGIN'
        elif 'Invalid user' in line:
            entry['event_type'] = 'INVALID_USER'
        else:
            entry['event_type'] = 'OTHER'

        if ' for ' in line and ' from ' in line:
            try:
                after_for = line.split(' for ')[1]
                entry['username'] = after_for.split(' ')[0]
            except:
                pass

        if ' from ' in line:
            try:
                after_from = line.split(' from ')[1]
                entry['ip_address'] = after_from.split(' ')[0]
            except:
                pass

        return entry

    def detect_threats(self, parsed_entries):
        """
        Phase 2 core function — analyze all parsed entries and find attacks.

        How it works:
        1. Count how many times each IP failed login
        2. Count how many invalid usernames each IP tried
        3. Check if many different IPs are each failing a few times
        4. Generate alerts based on thresholds
        """

        # Dictionary to count failed logins per IP
        # Example: {'185.220.101.45': 8, '45.33.32.156': 5}
        ip_fail_count = {}

        # Dictionary to count invalid user attempts per IP
        ip_invalid_count = {}

        # List to collect all alerts found
        alerts = []

        # --- Step 1: Count failures per IP ---
        for entry in parsed_entries:
            ip = entry['ip_address']

            if entry['event_type'] == 'FAILED_LOGIN':
                # If IP is already in dictionary, add 1
                # If IP is new, start count at 0 then add 1
                ip_fail_count[ip] = ip_fail_count.get(ip, 0) + 1

            if entry['event_type'] == 'INVALID_USER':
                ip_invalid_count[ip] = ip_invalid_count.get(ip, 0) + 1

        # --- Step 2: Check for brute force ---
        # Any IP that failed 5+ times is doing a brute force attack
        for ip, count in ip_fail_count.items():

            if count >= self.critical_threshold:
                # Very high number of attempts = critical threat
                alerts.append({
                    'severity': 'CRITICAL',
                    'threat_type': 'BRUTE_FORCE',
                    'ip': ip,
                    'count': count,
                    'description': f"Extreme brute force — {count} failed attempts"
                })

            elif count >= self.brute_force_threshold:
                # 5-9 attempts = high severity
                alerts.append({
                    'severity': 'HIGH',
                    'threat_type': 'BRUTE_FORCE',
                    'ip': ip,
                    'count': count,
                    'description': f"Brute force detected — {count} failed attempts"
                })

        # --- Step 3: Check for user enumeration ---
        # Attacker trying many different usernames = mapping the system
        for ip, count in ip_invalid_count.items():
            if count >= 3:
                alerts.append({
                    'severity': 'HIGH',
                    'threat_type': 'USER_ENUMERATION',
                    'ip': ip,
                    'count': count,
                    'description': f"User enumeration — {count} invalid usernames tried"
                })

        # --- Step 4: Check for distributed attack ---
        # Many different IPs each failing 1-2 times = coordinated attack
        # Count how many unique IPs have at least 1 failed login
        attacking_ips = [ip for ip, count in ip_fail_count.items() if count >= 1]

        if len(attacking_ips) >= 4:
            alerts.append({
                'severity': 'MEDIUM',
                'threat_type': 'DISTRIBUTED_ATTACK',
                'ip': f"{len(attacking_ips)} different IPs",
                'count': len(attacking_ips),
                'description': f"Possible distributed attack — {len(attacking_ips)} unique attacking IPs"
            })

        return alerts, ip_fail_count, ip_invalid_count

    def analyze(self):
        """Parse all entries then run threat detection"""
        if not self.log_entries:
            print("No log entries loaded.")
            return

        print("\n" + "="*60)
        print("  LOG ANALYZER - Phase 2: Threat Detection")
        print("  Author: Rishabh Raj")
        print("="*60)

        # Step 1: Parse every line (same as Phase 1)
        parsed_entries = []
        for line in self.log_entries:
            entry = self.parse_entry(line)
            parsed_entries.append(entry)

        # Count event types for summary
        failed = sum(1 for e in parsed_entries if e['event_type'] == 'FAILED_LOGIN')
        success = sum(1 for e in parsed_entries if e['event_type'] == 'SUCCESSFUL_LOGIN')
        invalid = sum(1 for e in parsed_entries if e['event_type'] == 'INVALID_USER')

        print(f"\nFile: {self.log_file}")
        print(f"Total lines: {self.total_lines}")
        print(f"\nEvent summary:")
        print(f"  Failed logins    : {failed}")
        print(f"  Successful logins: {success}")
        print(f"  Invalid users    : {invalid}")

        # Step 2: Run threat detection (NEW in Phase 2)
        alerts, ip_fail_count, ip_invalid_count = self.detect_threats(parsed_entries)

        # Step 3: Show IP failure breakdown
        print(f"\n{'='*60}")
        print("  IP ADDRESS ANALYSIS")
        print("="*60)
        print(f"\n{'IP Address':<20} {'Failed Attempts':<20} {'Risk Level'}")
        print("-" * 55)

        for ip, count in sorted(ip_fail_count.items(),
                                  key=lambda x: x[1],
                                  reverse=True):
            # Show risk level based on count
            if count >= self.critical_threshold:
                risk = "CRITICAL"
            elif count >= self.brute_force_threshold:
                risk = "HIGH"
            elif count >= 3:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            print(f"{ip:<20} {count:<20} {risk}")

        # Step 4: Show all alerts
        print(f"\n{'='*60}")
        print(f"  THREAT ALERTS ({len(alerts)} found)")
        print("="*60)

        if not alerts:
            print("\n  No threats detected.")
        else:
            for i, alert in enumerate(alerts, 1):
                print(f"\n  Alert #{i}")
                print(f"  Severity   : {alert['severity']}")
                print(f"  Threat type: {alert['threat_type']}")
                print(f"  Source IP  : {alert['ip']}")
                print(f"  Details    : {alert['description']}")
                print(f"  {'-'*40}")

        # Step 5: SOC recommendation
        print(f"\n{'='*60}")
        print("  SOC ANALYST RECOMMENDATION")
        print("="*60)

        critical_alerts = [a for a in alerts if a['severity'] == 'CRITICAL']
        high_alerts = [a for a in alerts if a['severity'] == 'HIGH']

        if critical_alerts:
            print("\n  [URGENT] Block these IPs immediately:")
            for alert in critical_alerts:
                print(f"    → {alert['ip']}")

        if high_alerts:
            print("\n  [ACTION] Investigate these IPs:")
            for alert in high_alerts:
                print(f"    → {alert['ip']} — {alert['description']}")

        if not alerts:
            print("\n  Network activity appears normal.")
            print("  Continue monitoring.")

        print("\n" + "="*60)
        return parsed_entries, alerts


def main():
    print("\n" + "="*60)
    print("  LOG FILE ANALYZER - Network Security Tool")
    print("  Author: Rishabh Raj | Phase 2: Threat Detection")
    print("="*60)

    analyzer = LogAnalyzer()

    filepath = input("\nEnter path to log file (or press Enter for sample): ").strip()

    if not filepath:
        filepath = "sample_logs/auth.log"

    if analyzer.load_log_file(filepath):
        analyzer.analyze()
    else:
        print("Could not load file. Check the path and try again.")


if __name__ == "__main__":
    main()