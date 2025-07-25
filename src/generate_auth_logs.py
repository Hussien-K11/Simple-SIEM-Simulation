# generate_auth_logs.py

import pandas as pd
import random
from datetime import datetime, timedelta

# -------------------------------
# 🧠 CONFIGURATION & SETUP
# -------------------------------

# Define usernames — mix of normal and privileged
users = [
    'alice', 'bob', 'charlie', 'david', 'eve',
    'admin', 'root', 'support', 'hr_user', 'finance_user'
]

# List of countries for geolocation simulation
countries = ['United Kingdom', 'United States', 'Germany', 'Russia', 'India', 'China', 'Brazil']

# IP ranges for variety
normal_ips = ['192.168.1.' + str(i) for i in range(5, 20)]
internal_ips = ['10.0.0.' + str(i) for i in range(30, 45)]
vpn_ips = ['172.16.0.' + str(i) for i in range(10, 20)]
suspicious_ips = ['85.111.23.6', '102.133.9.88', '212.45.99.5']  # Known risky regions or flagged

ip_pool = normal_ips + internal_ips + vpn_ips + suspicious_ips

# Log output list
log_entries = []

# Start time
start_time = datetime(2025, 7, 21, 8, 0, 0)

# -------------------------------
# 🔁 GENERATE 150 LOGS
# -------------------------------

for i in range(150):
    # Add random time gap
    timestamp = start_time + timedelta(seconds=random.randint(0, 7200))  # over 2 hrs
    username = random.choice(users)
    source_ip = random.choice(ip_pool)
    location = random.choice(countries)
    status = random.choices(['SUCCESS', 'FAIL'], weights=[0.25, 0.75])[0]

    # ---------------------------------------
    # 🚨 Inject Brute-Force Attack (clustered)
    if i in range(10, 15):
        username = 'alice'
        source_ip = '192.168.1.5'
        location = 'United Kingdom'
        status = 'FAIL'
    elif i == 15:
        username = 'alice'
        source_ip = '192.168.1.5'
        location = 'United Kingdom'
        status = 'SUCCESS'

    # ---------------------------------------
    # 🛑 Credential Stuffing Across Accounts
    elif i in range(30, 35):
        source_ip = '10.0.0.44'
        username = users[i % len(users)]
        location = 'Brazil'
        status = 'FAIL'
    elif i == 35:
        source_ip = '10.0.0.44'
        username = 'charlie'
        location = 'Brazil'
        status = 'SUCCESS'

    # ---------------------------------------
    # 🌍 Geolocation Anomaly (impossible travel)
    elif i == 50:
        username = 'bob'
        source_ip = '192.168.1.7'
        location = 'United Kingdom'
        status = 'SUCCESS'
    elif i == 51:
        username = 'bob'
        source_ip = '85.111.23.6'
        location = 'Russia'
        timestamp += timedelta(minutes=1)
        status = 'SUCCESS'

    # ---------------------------------------
    # 🐌 Low-and-Slow Brute Force
    elif i in [60, 80, 100, 120]:
        username = 'eve'
        source_ip = '10.0.0.31'
        location = 'United States'
        status = 'FAIL'

    # ---------------------------------------
    # 🔐 Rare Privileged Account Access
    elif username in ['root', 'admin', 'support'] and random.random() < 0.5:
        location = 'China'
        status = 'FAIL'

    # ---------------------------------------
    # 🌙 Night-Time Login (anomaly)
    elif i == 140:
        timestamp = datetime(2025, 7, 21, 3, 30, 0)
        username = 'hr_user'
        source_ip = '172.16.0.14'
        location = 'United Kingdom'
        status = 'SUCCESS'

    # Add the generated log to the list
    log_entries.append({
        'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'username': username,
        'source_ip': source_ip,
        'status': status,
        'location': location
    })

# -------------------------------
# 💾 EXPORT TO CSV
# -------------------------------

df = pd.DataFrame(log_entries)
df = df.sort_values(by='timestamp')  # keep logs in order

import os

# Get the full path safely, regardless of where the script is run from
base_dir = os.path.dirname(os.path.dirname(__file__))  # goes up from /src/
output_path = os.path.join(base_dir, 'data', 'auth_logs.csv')

df.to_csv(output_path, index=False)

print("[+] ✅ New dataset saved to data/auth_logs.csv with", len(df), "entries.")
