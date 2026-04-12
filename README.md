# Log File Analyzer 🔍

> A Python security tool that parses SSH authentication logs, detects threats, and generates professional incident reports — built to understand how SIEM tools like Splunk work under the hood.

**Author:** Rishabh Raj | Aspiring SOC Analyst
**GitHub:** [rishabhraj2754](https://github.com/Rishabhraj2754) | **LinkedIn:** [Rishabh Raj](https://www.linkedin.com/in/rishabhraj2754)

---

## What problem does this solve?

Every server writes a log file when someone tries to log in. A real attack leaves hundreds of lines like this:

    Failed password for root from 185.220.101.45 port 4444
    Failed password for root from 185.220.101.45 port 4445
    Failed password for root from 185.220.101.45 port 4446

A SOC analyst's job is to find these patterns inside 50,000 lines. This tool automates that — exactly like Splunk does, but built from scratch in Python.

---

## How to run it

    git clone https://github.com/Rishabhraj2754/LogAnalyzer-Tool.git
    cd LogAnalyzer-Tool
    python3 log_analyzer.py

Press Enter when asked for file path. No external libraries needed.

---

## Project phases

| Phase | What it builds | Status |
|-------|---------------|--------|
| Phase 1 | Log parsing — read and classify every line | ✅ Complete |
| Phase 2 | Threat detection — brute force, enumeration, distributed attacks | ✅ Complete |
| Phase 3 | CSV incident report + security dashboard | ✅ Complete |
| Phase 4 | Advanced features — threading, email alerts | 🔄 Future |

---

## Phase 1 — Log Parsing ✅

### What it does
Opens a raw SSH auth log, reads every line, classifies each event, extracts IP address and username.

### What I learned
- How SSH authentication logs are structured
- String parsing with split() — the same technique SIEM tools use internally
- How to extract structured data from raw unstructured text
- File handling with open() and context managers

### Key code

    def parse_entry(self, line):
        parts = line.split()
        entry['date'] = f"{parts[0]} {parts[1]} {parts[2]}"

        if 'Failed password' in line:
            entry['event_type'] = 'FAILED_LOGIN'
        elif 'Accepted password' in line:
            entry['event_type'] = 'SUCCESSFUL_LOGIN'
        elif 'Invalid user' in line:
            entry['event_type'] = 'INVALID_USER'

        after_from = line.split(' from ')[1]
        entry['ip_address'] = after_from.split(' ')[0]

### Output

    LOG ANALYZER - Phase 1: Log Parsing
    ============================================================
    File: sample_logs/auth.log
    Total lines: 30

    Event breakdown:
      Failed logins    : 22
      Successful logins: 4
      Invalid users    : 4

    ALL PARSED ENTRIES
    [x]  Jan 15 10:21:01 | FAILED_LOGIN     | User: root    | IP: 185.220.101.45
    [OK] Jan 15 10:22:10 | SUCCESSFUL_LOGIN | User: rishabh | IP: 10.0.0.5
    [?]  Jan 15 10:26:00 | INVALID_USER     | User: Unknown | IP: 222.186.42.117

### Git commit message
    Phase 1: Log parsing complete - reads SSH auth logs, classifies events, extracts IPs and usernames

---

## Phase 2 — Threat Detection ✅

### What it does
Counts failed login attempts per IP, detects three attack types, fires severity-rated alerts automatically.

### Three threats detected

**Brute Force** — same IP failing 5 or more times

    185.220.101.45 failed 11 times → CRITICAL alert
    45.33.32.156 failed 6 times   → HIGH alert

**User Enumeration** — attacker trying usernames that do not exist on the server

    222.186.42.117 tried: testuser, admin123, administrator, guest
    Attacker is mapping what accounts exist before attacking → HIGH alert

**Distributed Attack** — many different IPs each failing a few times to avoid detection

    6 unique attacking IPs detected → MEDIUM alert

### What I learned
- Threshold-based detection — the foundation of every SIEM alert rule
- Dictionary counting pattern to track events per source IP
- How Splunk correlation searches work under the hood
- Difference between brute force, enumeration, and distributed attacks

### Key code

    def detect_threats(self, parsed_entries):
        ip_fail_count = {}

        for entry in parsed_entries:
            if entry['event_type'] == 'FAILED_LOGIN':
                ip = entry['ip_address']
                ip_fail_count[ip] = ip_fail_count.get(ip, 0) + 1

        for ip, count in ip_fail_count.items():
            if count >= 10:
                alerts.append({'severity': 'CRITICAL', 'threat_type': 'BRUTE_FORCE'})
            elif count >= 5:
                alerts.append({'severity': 'HIGH', 'threat_type': 'BRUTE_FORCE'})

### Output

    THREAT ALERTS (4 found)

    Alert #1
    Severity   : CRITICAL
    Threat type: BRUTE_FORCE
    Source IP  : 185.220.101.45
    Details    : Extreme brute force — 11 failed attempts

    Alert #2
    Severity   : HIGH
    Threat type: USER_ENUMERATION
    Source IP  : 222.186.42.117
    Details    : User enumeration — 4 invalid usernames tried

    SOC ANALYST RECOMMENDATION
    [URGENT] Block these IPs immediately:
      --> 185.220.101.45
    [ACTION] Investigate these IPs:
      --> 45.33.32.156

### Git commit message
    Phase 2: Threat detection complete - auto-detects brute force, user enumeration and distributed attacks

---

## Phase 3 — Incident Reporting ✅

### What it does
Saves all detected threats to a timestamped CSV file and prints a security dashboard with overall risk rating.

### What I learned
- CSV module — writing structured data that opens cleanly in Excel
- Datetime timestamps — every security report needs when it happened
- How SOC analysts document and escalate incidents
- Severity-based recommendations for each threat level

### Key code

    def save_to_csv(self, alerts):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"report_{timestamp}.csv"

        with open(filepath, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for alert in alerts:
                if alert['severity'] == 'CRITICAL':
                    recommendation = "BLOCK IP IMMEDIATELY"
                elif alert['severity'] == 'HIGH':
                    recommendation = "INVESTIGATE AND BLOCK"
                writer.writerow({
                    'Severity': alert['severity'],
                    'Source_IP': alert['ip'],
                    'Recommendation': recommendation
                })

### CSV report saved automatically

    reports/report_2026-04-12_15-24-54.csv

When opened in Excel it shows: Timestamp, Threat Type, Severity, Source IP, Attempt Count, Description, Recommendation — one row per threat.

### Security dashboard output

    SECURITY DASHBOARD — FINAL SUMMARY
    ============================================================
    Total threats detected : 4
    CRITICAL               : 1
    HIGH                   : 2
    MEDIUM                 : 1
    LOW                    : 0

    Overall network risk: *** CRITICAL — IMMEDIATE ACTION REQUIRED ***

### Git commit message
    Phase 3: CSV export and incident reporting complete - security dashboard with severity scoring

---

## How this tool connects to real SOC work

    Real SOC workflow:
    Server gets attacked
    → logs fill up
    → analyst opens SIEM (Splunk)
    → Splunk parses logs
    → correlation rule fires alert
    → analyst investigates
    → documents incident in ticket

    This tool:
    auth.log file
    → load_log_file() reads every line
    → parse_entry() classifies each event
    → detect_threats() counts and fires alerts
    → save_to_csv() documents the incident
    → print_dashboard() shows overall risk

The logic is identical. Splunk has a GUI and costs $50,000 per year. This does the same thing in 300 lines of Python.

---

## Event type reference

| Symbol | Event | Meaning | Threat Level |
|--------|-------|---------|--------------|
| [x] | FAILED_LOGIN | Wrong password attempt | Medium |
| [OK] | SUCCESSFUL_LOGIN | Login succeeded | Low |
| [?] | INVALID_USER | Username does not exist on server | High |
| [-] | OTHER | Unclassified event | Low |

## Severity reference

| Severity | Trigger | Recommendation |
|----------|---------|----------------|
| CRITICAL | 10 or more failed attempts from one IP | Block IP immediately |
| HIGH | 5 or more failed attempts, or 3 or more invalid users | Investigate and block |
| MEDIUM | 4 or more unique attacking IPs | Monitor closely |
| LOW | Single failed attempts | Log and watch |

---

## Related project

**[PortScanner Tool](https://github.com/Rishabhraj2754/PortScanner-Tool)** — Network port scanning tool that identifies open ports and running services. Together these two projects cover the core skills tested in L1 SOC analyst interviews: network reconnaissance and log analysis.

---

*Building in public — follow my progress on [LinkedIn](https://www.linkedin.com/in/rishabhraj2754)*