# Simple-SIEM-Simulation

## 1. Project Overview

This project simulates real-world detection logic across multiple log sources using both Python and Splunk Cloud. It reflects the typical workflows of a Tier 1 SOC analyst: reviewing logs, writing detection logic, triaging suspicious events, and documenting results. The goal is to demonstrate strong analytical thinking, clarity of documentation, and readiness for a modern SOC environment.

The simulation includes three distinct log types:
- DNS logs
- Windows Event logs
- Authentication logs

Each log source is used to write detections that reflect real-world attack behaviours such as command-and-control (C2) lookups, brute-force attempts, and privilege escalation indicators.

---

## 2. Project Structure

| Phase      | Description                                          | Tools             |
|------------|------------------------------------------------------|-------------------|
| Phase 1    | Python-based detection logic and simulation          | Jupyter, pandas   |
| Phase 2    | Detection logic replicated and tested in Splunk Cloud| Splunk Cloud, SPL |

---

## 3. DNS Log Detections  
**Data Source:** `dns_logs.csv`

| Rule # | Detection Description |
|--------|------------------------|
| 1 | Suspicious DNS queries to known-bad or randomised domains |

<details>
<summary>Rule 1 – Suspicious DNS Query Detection</summary>

**Analyst Note:**  
This rule identifies potentially malicious DNS requests. It looks for domains that contain suspicious keywords (e.g., `.ru`, `.xyz`, `malicious`) or appear to be base64-like encoded strings. These types of queries are often linked to malware attempting to contact its command-and-control servers.

To reduce noise, we also filter for DNS response codes like `NXDOMAIN` or `SERVFAIL`, which indicate failed lookups—often a sign of malware probing for non-existent domains.

**Logic Summary:**
- Search for suspicious TLDs and strings
- Match base64-style domains using regex
- Filter only failed DNS lookups to reduce false positives

**Screenshots:**
![Preview of raw DNS logs](screenshots/jupyter/dns/dns_logs_preview.png)  
![Suspicious queries - part 1](screenshots/jupyter/dns/dns_rule1_suspicious_queries(1).png)  
![Suspicious queries - part 2](screenshots/jupyter/dns/dns_rule1_suspicious_queries(2).png)


</details>

---

## 4. Windows Log Detections  
**Data Source:** `windows_logs.csv`

| Rule # | Detection Description |
|--------|------------------------|
| 1 | _Planned: Detection of suspicious process execution_ |
| 2 | _Planned: Event ID 4625 (failed logins) correlation_ |
| 3 | _Planned: Privilege escalation via unusual logon type and process combo_ |

_(Detection logic under development. Will include correlation of process names, event IDs, and privilege usage patterns for insider threat simulation.)_

---

## 5. Authentication Log Detections  
**Data Source:** `auth_logs.csv`

| Rule # | Detection Description |
|--------|------------------------|
| 1 | 5+ failed logins from same IP within 60 seconds |
| 2 | 5+ unique usernames attempted from same IP within 60 seconds |
| 3 | Successful login after multiple failures from the same IP in 10 mins |

<details>
<summary>Rule 1 – Brute-Force Login Detection</summary>

**Analyst Note:**  
This rule identifies brute-force behaviour by flagging 5 or more failed login attempts from the same IP address within one minute. This is a common first step in account compromise attempts.

**Logic Summary:**
- Filter logins with status 'FAIL'
- Group by source IP and timestamp
- Trigger alert if 5+ events occur within 60 seconds

**Screenshot:**  
_Add relevant screenshot from `auth_rule1_bruteforce_output.png`_

</details>

<details>
<summary>Rule 2 – Password Spraying Detection</summary>

**Analyst Note:**  
Detects horizontal spraying attacks where multiple usernames are targeted from one IP in a short window. Unlike brute-force, this technique avoids locking any one account but still tests weak passwords.

**Logic Summary:**
- Count unique usernames attempted from one IP
- Trigger alert if 5+ usernames are attempted in 1 minute

**Screenshot:**  
_Add relevant screenshot from `auth_rule2_passwordspray_output.png`_

</details>

<details>
<summary>Rule 3 – Success After Failures</summary>

**Analyst Note:**  
Flags suspicious successful logins that were immediately preceded by 3 or more failures from the same source IP within the past 10 minutes. This pattern often indicates a guessed or compromised password.

**Logic Summary:**
- Check if a success is preceded by recent failures
- Filter for same IP and narrow time window

**Screenshot:**  
_Add relevant screenshot from `auth_rule3_success_after_fail.png`_

</details>

---

## 6. Splunk Cloud SIEM (Phase 2)

This next stage will mirror all detection logic in Splunk Cloud, allowing for:
- SIEM-style alerting and dashboard creation
- Field extraction and log tagging
- Hands-on experience with SPL (Search Processing Language)

**Upcoming Steps:**
- [ ] Upload all `.csv` log files to Splunk Cloud
- [ ] Rebuild Python logic in SPL
- [ ] Create dashboards to simulate alert triage
- [ ] Include Splunk output screenshots in `README.md`

---

## 7. Skills Demonstrated

- Detection engineering across multiple log types
- Time-based filtering and alert logic using Python
- Regular expression design for DNS anomaly detection
- Log enrichment and behavioural analysis
- Cross-platform thinking (Jupyter to Splunk)
- Documentation of technical reasoning and alerts

---

## 8. Screenshots Directory

All screenshots mentioned above are located in the `/screenshots/` folder. Each filename corresponds to the relevant rule output.

---

## 9. Let’s Connect

**Hussien Kofi**  
Aspiring SOC Analyst | Threat-Informed | Detection-Focused

- [Email](mailto:Hussienkofi@gmail.com)  
- [LinkedIn](https://www.linkedin.com/in/hussien-kofi-99a012330/)  
- [GitHub](https://github.com/Hussien-K11)

This project is part of a hands-on cybersecurity portfolio focused on building a foundational understanding of log-based threat detection, SIEM integration, and practical alert development. Every detection rule was written with the mindset of a junior analyst preparing to work in a real SOC.
