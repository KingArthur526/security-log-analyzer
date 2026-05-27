# Security Log Analyzer & Anomaly Detector

## Overview

This project is a Python-based real-time security log analyzer designed to detect suspicious activity and common web attacks from Apache and Nginx access logs.

The analyzer monitors log files continuously, identifies malicious patterns using regex-based detection, and generates security alerts for potential intrusion attempts and abnormal traffic behavior.

The project demonstrates practical cybersecurity concepts including:
- Log analysis
- Threat detection
- Real-time monitoring
- Behavioral analysis
- OWASP attack detection
- Security event analysis

---

# Features

## Real-Time Log Monitoring
- Continuously monitors Apache/Nginx access logs
- Detects new events as they are written to the file

## Attack Detection
Detects:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection

## Behavioral Analysis
- Brute-force login detection
- High traffic anomaly detection
- Request threshold monitoring

## Alert System
- Severity-based alerts
- Threat scoring
- JSON alert exports
- Live terminal notifications

## Dashboard
Displays:
- Attack statistics
- Severity statistics
- Live monitoring information

---

# Technologies Used

- Python
- regex
- threading
- collections
- JSON
- file handling

---

# Architecture

```text
Access Logs
     ↓
Log Parser
     ↓
Signature Detection
     ↓
Behavioral Analysis
     ↓
Threat Scoring
     ↓
Alert Generation
     ↓
Dashboard & JSON Reports
```

---

# Usage

Run the program:

```bash
python log_analyzer.py
```

Example input:

```txt
Enter log file path: access.log
```

---

# Example Log Entries

```txt
192.168.1.10 - - [25/May/2026:10:10:11] "GET /login.php?id=' OR 1=1 -- HTTP/1.1" 200

192.168.1.12 - - [25/May/2026:10:10:12] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200

192.168.1.13 - - [25/May/2026:10:10:13] "GET /../../etc/passwd HTTP/1.1" 404
```

---

# Example Output

```txt
[!] SECURITY ALERT

IP        : 192.168.1.10
Attack    : SQL Injection
Severity  : MEDIUM
Score     : 50
```

---

# Detection Techniques

## Signature-Based Detection
Uses regex pattern matching to identify:
- SQLi payloads
- XSS payloads
- path traversal attempts
- command injection patterns

## Behavioral Detection
Monitors:
- repeated failed logins
- excessive requests
- abnormal traffic spikes

---

# Educational Purpose

This project was developed for educational and research purposes to better understand:
- Security monitoring
- Intrusion detection
- SIEM-style workflows
- Log analysis techniques
- Threat detection methodologies
- Web attack patterns

---

# Limitations

This tool performs lightweight detection using:
- regex signatures
- threshold-based anomaly detection

It does not:
- perform deep packet inspection
- use machine learning
- replace enterprise SIEM solutions

The project is intended as an educational cybersecurity monitoring tool.
