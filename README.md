# Log File Analyzer 🔍

> A Python security tool that parses SSH authentication logs, detects threats, and classifies security events — built to understand how SIEM tools like Splunk work under the hood.

**Author:** Rishabh Raj | Aspiring SOC Analyst  
**GitHub:** [rishabhraj2754](https://github.com/Rishabhraj2754) | **LinkedIn:** [Rishabh Raj](https://www.linkedin.com/in/rishabhraj2754)

---

## What problem does this solve?

Every server writes a log file when someone tries to log in. A real attack leaves hundreds of lines like this:
```
Failed password for root from 185.220.101.45 port 4444
Failed password for root from 185.220.101.45 port 4445
Failed password for root from 185.220.101.45 port 4446
```

A SOC analyst's job is to find these patterns inside 50,000 lines. This tool automates that — exactly like Splunk does, but built from scratch in Python.

---

## Live output — Phase 1
```
============================================================
  LOG ANALYZER - Phase 1: Log Parsing
  Author: Rishabh Raj
============================================================

File analyzed : sample_logs/auth.log
Total entries : 18

Event breakdown:
  Failed logins    : 13
  Successful logins: 3
  Invalid users    : 2
  Other events     : 0

============================================================
  ALL PARSED ENTRIES
============================================================
[x]  Jan 15 10:21:01 | FAILED_LOGIN         | User: root     | IP: 185.220.101.45
[x]  Jan 15 10:21:02 | FAILED_LOGIN         | User: root     | IP: 185.220.101.45
[OK] Jan 15 10:22:10 | SUCCESSFUL_LOGIN     | User: rishabh  | IP: 10.0.0.5
[x]  Jan 15 10:23:15 | FAILED_LOGIN         | User: admin    | IP: 45.33.32.156
[?]  Jan 15 10:26:00 | INVALID_USER         | User: Unknown  | IP: 222.186.42.117
```

---

## How it works
```
auth.log file (raw text)
        ↓
load_log_file()    → reads every line, strips whitespace
        ↓
parse_entry()      → breaks each line into: date, event type, username, IP
        ↓
analyze()          → counts events, prints classified results
        ↓
Terminal output    → human-readable security report
```

---

## What each event type means

| Symbol | Event | Meaning | Threat Level |
|--------|-------|---------|--------------|
| `[x]` | FAILED_LOGIN | Wrong password attempt | Medium |
| `[OK]` | SUCCESSFUL_LOGIN | Login succeeded | Low |
| `[?]` | INVALID_USER | Username doesn't exist | High |
| `[-]` | OTHER | Unclassified event | Low |

---

## How to run it
```bash
# Clone the repo
git clone https://github.com/Rishabhraj2754/LogAnalyzer-Tool.git
cd LogAnalyzer-Tool

# Run with sample log
python3 log_analyzer.py

# Press Enter to use sample_logs/auth.log
# Or type your own log file path
```

No external libraries needed — uses Python built-ins only.

---

## Project phases

| Phase | What it builds | Status |
|-------|---------------|--------|
| Phase 1 | Log parsing — read and classify every line | ✅ Complete |
| Phase 2 | Threat detection — auto-detect brute force attacks | 🔄 In progress |
| Phase 3 | Severity scoring — rank threats critical/high/medium | ⏳ Planned |
| Phase 4 | CSV export — professional security report | ⏳ Planned |

---

## What I learned building this

**Python skills:**
- File handling with `open()` and context managers
- String parsing with `split()` — the same logic SIEM tools use
- Dictionary data structures for structured log entries
- Loop logic for processing thousands of lines

**Security concepts:**
- SSH authentication log format
- Difference between failed login, successful login, and invalid user
- How brute force attacks appear in logs
- Why log analysis is the core skill of a SOC analyst

---

## Connection to real SOC work

This project simulates what happens every day in a Security Operations Center:
```
Real SOC workflow:
Server gets attacked → logs fill up → analyst opens SIEM (Splunk)
→ Splunk parses logs → shows classified events → analyst investigates

This project:
auth.log created → python reads it → parse_entry() classifies
→ analyze() shows results → you investigate
```

The logic is identical. The difference is Splunk has a GUI and costs $50,000/year.

---

## Related project

**[PortScanner Tool](https://github.com/Rishabhraj2754/PortScanner-Tool)** — Network port scanning tool that identifies open ports and running services. Together these two tools demonstrate core network reconnaissance and log analysis skills required for SOC roles.

---

*Building phase by phase — follow my progress on [LinkedIn](https://www.linkedin.com/in/rishabhraj2754)*