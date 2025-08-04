import os
import pandas as pd
from datetime import datetime, timedelta
import random

# ------------------------
# Simulate Windows Event Logs
# ------------------------

# Common user accounts
usernames = ["alice", "bob", "charlie", "admin", "guest"]

# Simulated host machines
hosts = ["WORKSTATION-01", "SERVER-02", "HR-PC", "FINANCE-LAPTOP"]

# Event IDs and their meanings
event_types = [
    {"event_id": 4624, "event_type": "Logon Success"},
    {"event_id": 4625, "event_type": "Logon Failure"},
    {"event_id": 4672, "event_type": "Privilege Escalation"},
    {"event_id": 4688, "event_type": "Process Created"},
    {"event_id": 4720, "event_type": "New User Account Created"},
    {"event_id": 9999, "event_type": "Mimikatz Execution"}  # Custom threat sim
]

# Logon types (based on real Windows values)
logon_types = {
    2: "Interactive",
    3: "Network",
    10: "RemoteDesktop"
}

# Suspicious and benign processes
process_names = [
    "explorer.exe", "chrome.exe", "powershell.exe", "cmd.exe",
    "svchost.exe", "mimikatz.exe", "rundll32.exe"
]

logs = []
start_time = datetime(2025, 7, 21, 11, 0, 0)

for i in range(100):
    timestamp = start_time + timedelta(seconds=i * random.randint(10, 30))
    user = random.choice(usernames)
    host = random.choice(hosts)
    event = random.choice(event_types)
    logon_code = random.choice(list(logon_types.keys()))
    process = random.choice(process_names)

    # Only include privilege field for privilege escalation or mimikatz
    privilege = "SeDebugPrivilege" if event["event_id"] in [4672, 9999] else None

    logs.append({
        "timestamp": timestamp,
        "event_id": event["event_id"],
        "event_type": event["event_type"],
        "username": user,
        "host": host,
        "logon_type": logon_types[logon_code],
        "process_name": process,
        "privilege_used": privilege
    })

# Convert to DataFrame
df = pd.DataFrame(logs)

# Save to CSV
os.makedirs("data", exist_ok=True)
df.to_csv("data/windows_logs.csv", index=False)
print("[+] ✅ Windows logs (v2) saved to data/windows_logs.csv")
