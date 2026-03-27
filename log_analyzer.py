#!/usr/bin/env python3
"""
LOG FILE ANALYZER - Security Tool
Author: Rishabh Raj
Purpose: Parse and analyze security log files to detect threats
Phase 1: Read and parse log files
"""

import os
from datetime import datetime

class LogAnalyzer:
    def __init__(self):
        self.log_file = None
        self.log_entries = []
        self.total_lines = 0

    def load_log_file(self, filepath):
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

    def analyze(self):
        if not self.log_entries:
            print("No log entries loaded. Run load_log_file() first.")
            return

        print("\n" + "="*60)
        print("  LOG ANALYZER - Phase 1: Log Parsing")
        print("  Author: Rishabh Raj")
        print("="*60)

        parsed_entries = []

        for line in self.log_entries:
            entry = self.parse_entry(line)
            parsed_entries.append(entry)

        failed = 0
        success = 0
        invalid = 0
        other = 0

        for entry in parsed_entries:
            if entry['event_type'] == 'FAILED_LOGIN':
                failed += 1
            elif entry['event_type'] == 'SUCCESSFUL_LOGIN':
                success += 1
            elif entry['event_type'] == 'INVALID_USER':
                invalid += 1
            else:
                other += 1

        print(f"\nFile analyzed : {self.log_file}")
        print(f"Total entries : {self.total_lines}")
        print(f"\nEvent breakdown:")
        print(f"  Failed logins    : {failed}")
        print(f"  Successful logins: {success}")
        print(f"  Invalid users    : {invalid}")
        print(f"  Other events     : {other}")

        print(f"\n{'='*60}")
        print("  ALL PARSED ENTRIES")
        print("="*60)

        for entry in parsed_entries:
            if entry['event_type'] == 'FAILED_LOGIN':
                symbol = 'x'
            elif entry['event_type'] == 'SUCCESSFUL_LOGIN':
                symbol = 'OK'
            elif entry['event_type'] == 'INVALID_USER':
                symbol = '?'
            else:
                symbol = '-'

            print(f"[{symbol}] {entry['date']} | {entry['event_type']:20s} | "
                  f"User: {entry['username']:12s} | IP: {entry['ip_address']}")

        print("="*60)
        return parsed_entries


def main():
    print("\n" + "="*60)
    print("  LOG FILE ANALYZER - Network Security Tool")
    print("  Author: Rishabh Raj | Phase 1: Log Parsing")
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