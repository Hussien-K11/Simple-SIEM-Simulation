import os
import pandas as pd
from datetime import datetime, timedelta
import random

# ------------------------
# Simulate DNS Query Logs
# ------------------------

# Sample source IPs making DNS requests
ips = ["192.168.1.10", "10.0.0.5", "172.16.0.7", "192.168.1.15", "192.168.1.25"]

# Common + suspicious domain queries (with odd TLDs & DNS tunneling patterns)
domains = [
    "google.com", "microsoft.com", "bbc.co.uk", "secure-login.net",  # Legit
    "malicious.ru", "stealer.cn", "phishing.xyz",  # Suspicious
    "dGhpcy5pcwBhLnRlc3Q=", "YXNkZmcxMjMuZXhhbXBsZS5jb20=",  # Simulated DNS tunneling
]

# DNS response codes
response_codes = ["NOERROR", "NXDOMAIN", "SERVFAIL"]

# Processes that might trigger DNS lookups
processes = [
    "chrome.exe", "powershell.exe", "outlook.exe", "svchost.exe", "cmd.exe", "unknown.exe"
]

logs = []

start_time = datetime(2025, 7, 21, 10, 0, 0)

for i in range(100):  # Generate 100 DNS log entries
    timestamp = start_time + timedelta(seconds=i * 20)  # One every 20 seconds
    ip = random.choice(ips)
    domain = random.choice(domains)
    response = random.choice(response_codes)
    process = random.choice(processes)

    logs.append({
        "timestamp": timestamp,
        "source_ip": ip,
        "queried_domain": domain,
        "response_code": response,
        "process_name": process
    })

# Convert to DataFrame
df = pd.DataFrame(logs)

# Save to CSV
os.makedirs("data", exist_ok=True)
df.to_csv("data/dns_logs.csv", index=False)
print("[+] ✅ DNS logs (v2) saved to data/dns_logs.csv")
