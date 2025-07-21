# src/log_ingestion.py

import pandas as pd
import os

def load_auth_logs(filepath):
    """
    Load authentication logs from a CSV file.
    Returns a pandas DataFrame.
    """
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        return None

    try:
        df = pd.read_csv(filepath)
        print("[+] Authentication logs loaded successfully.")
        return df
    except Exception as e:
        print(f"[!] Error reading CSV: {e}")
        return None

if __name__ == "__main__":
    # Relative path to your log file
    path = "D:/SOC-Journey/GitHub-Projects/Simple-SIEM-Simulation/data/auth_logs.csv"
    logs = load_auth_logs(path)

    if logs is not None:
        print("\n--- Preview of Log Data ---")
        print(logs.head())
