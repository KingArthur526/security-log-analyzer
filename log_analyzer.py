import re
import time
import json
import threading
from collections import defaultdict, deque
from datetime import datetime

LOG_FILE = "access.log"



SIGNATURES = {
    "SQL Injection": [
        r"(?i)(union\s+select)",
        r"(?i)(or\s+1=1)",
        r"(?i)(drop\s+table)"
    ],

    "XSS": [
        r"(?i)(<script>)",
        r"(?i)(javascript:)",
        r"(?i)(alert\()"
    ],

    "Path Traversal": [
        r"(\.\./)",
        r"(%2e%2e%2f)"
    ],

    "Command Injection": [
        r"(?i)(;)",
        r"(?i)(&&)",
        r"(?i)(whoami)"
    ]
}



TIME_WINDOW = 60
FAILED_LOGIN_LIMIT = 5
REQUEST_LIMIT = 25


failed_logins = defaultdict(deque)
request_count = defaultdict(deque)

attack_stats = defaultdict(int)
severity_stats = defaultdict(int)



THREAT_SCORES = {
    "SQL Injection": 50,
    "XSS": 40,
    "Path Traversal": 45,
    "Command Injection": 60,
    "Brute Force": 35,
    "High Traffic": 20
}


def get_ip(log):

    match = re.match(r"^(\d+\.\d+\.\d+\.\d+)", log)

    if match:
        return match.group(1)

    return "Unknown"


def get_severity(score):

    if score >= 60:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    return "LOW"


def print_alert(ip, attack, log):

    score = THREAT_SCORES.get(attack, 10)

    severity = get_severity(score)

    attack_stats[attack] += 1
    severity_stats[severity] += 1

    alert = {
        "time": str(datetime.now()),
        "ip": ip,
        "attack": attack,
        "severity": severity,
        "score": score,
        "log": log.strip()
    }

    print("\n" + "=" * 70)

    print("[!] SECURITY ALERT")

    print("=" * 70)

    print("Time      :", alert["time"])
    print("IP        :", ip)
    print("Attack    :", attack)
    print("Severity  :", severity)
    print("Score     :", score)

    print("\nLog:")
    print(log.strip())

    print("=" * 70)

  
    with open("alerts.json", "a") as f:

        f.write(json.dumps(alert) + "\n")


def detect_signatures(ip, log):

    for attack, patterns in SIGNATURES.items():

        for pattern in patterns:

            if re.search(pattern, log):

                print_alert(ip, attack, log)

                break



def detect_bruteforce(ip, log):

    if "401" in log or "login" in log.lower():

        current = time.time()

        failed_logins[ip].append(current)

        while failed_logins[ip]:

            if current - failed_logins[ip][0] > TIME_WINDOW:

                failed_logins[ip].popleft()

            else:
                break

        if len(failed_logins[ip]) >= FAILED_LOGIN_LIMIT:

            print_alert(ip, "Brute Force", log)



def detect_traffic(ip, log):

    current = time.time()

    request_count[ip].append(current)

    while request_count[ip]:

        if current - request_count[ip][0] > TIME_WINDOW:

            request_count[ip].popleft()

        else:
            break

    if len(request_count[ip]) >= REQUEST_LIMIT:

        print_alert(ip, "High Traffic", log)



def analyze(log):

    ip = get_ip(log)

    detect_signatures(ip, log)

    detect_bruteforce(ip, log)

    detect_traffic(ip, log)



def follow(file):

  
    for line in file:

        yield line

   
    while True:

        line = file.readline()

        if not line:

            time.sleep(0.1)

            continue

        yield line



def dashboard():

    while True:

        time.sleep(10)

        print("\n" + "#" * 70)

        print("LIVE DASHBOARD")

        print("#" * 70)

        print("\nAttack Statistics:\n")

        for attack, count in attack_stats.items():

            print(f"{attack:<20} : {count}")

        print("\nSeverity Statistics:\n")

        for sev, count in severity_stats.items():

            print(f"{sev:<20} : {count}")

        print("#" * 70)



print("=" * 70)
print(" SECURITY LOG ANALYZER & ANOMALY DETECTOR ")
print("=" * 70)

path = input("Enter log file path: ")

try:

    dashboard_thread = threading.Thread(
        target=dashboard,
        daemon=True
    )

    dashboard_thread.start()

    with open(path, "r") as logfile:

        logs = follow(logfile)

        for line in logs:

            analyze(line)

except FileNotFoundError:

    print("Log file not found.")