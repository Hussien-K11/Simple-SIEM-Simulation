# Simple-SIEM-Simulation

## 1. Project Overview

This project simulates real-world SOC detection workflows using structured logs and multi-platform detection logic across Python and Splunk. Inspired by enterprise practices, the goal is to demonstrate a threat-informed, framework-aligned approach to security monitoring — using detection logic that maps to the MITRE ATT&CK framework, and operational practices drawn from NIST CSF, NIST 800-61, and CIS Controls.

The project reflects Tier 1 SOC responsibilities such as:
- Reviewing DNS, Authentication, and Windows logs
- Writing detection logic in Python
- Correlating events and identifying suspicious behaviour
- Documenting detections and preparing escalation summaries

---

## 2. Project Structure

| Phase      | Description                                          | Tools             |
|------------|------------------------------------------------------|-------------------|
| Phase 1    | Python-based detection logic and simulation          | Jupyter, pandas   |
| Phase 2    | Detection logic replicated and tested in Splunk Cloud| Splunk Cloud, SPL |

---
## 3. Jupyter-Based Detection Logic

This section showcases detection rules written in Python using Jupyter notebooks. Each rule is designed to reflect real-world SOC workflows: reviewing logs, applying logic, filtering out noise, and flagging suspicious behaviour. Every rule is aligned with adversary techniques from the MITRE ATT&CK framework, mapped to NIST CSF functions, and rooted in practical detection goals from CIS Controls.

---

<details>
<summary><strong>DNS Log Detections</strong> — <em>Data Source: dns_logs.csv</em></summary>

| Rule # | Detection Description |
|--------|------------------------|
| 1 | Suspicious DNS queries to known-bad or randomised domains |
| 2 | [Planned] Repeated DNS queries to suspicious domains within short intervals |
| 3 | [Planned] DNS exfiltration pattern detection via encoded subdomains |

<details>
<summary>Rule 1 – Suspicious DNS Query Detection</summary>

**Analyst Note:**  
I wanted this rule to flag potential beaconing or command-and-control activity — but not every weird-looking domain is malicious. I fine-tuned the logic to catch base64-style strings and odd TLDs like `.ru` or `.xyz`, then filtered for failed lookups like `NXDOMAIN` to reduce false positives. The goal was to simulate how a SOC analyst would cut through noisy DNS logs.

**Framework Reference:**  
- **MITRE ATT&CK T1071.004** – Application Layer Protocol: DNS  
- **NIST CSF DE.AE-3**, **NIST SP 800-92** – Detect anomalies via failed resolution patterns  
- **CIS Control 13.8** – Monitor and alert on anomalous DNS activity

**Logic Summary:**
- Match encoded subdomains using regex
- Flag risky TLDs (e.g. `.ru`, `.xyz`)
- Filter for failed responses to catch dead or malicious lookups

<details>
<summary>View DNS Rule 1 Screenshots</summary>

_Preview of Raw DNS Logs_  
![Preview](screenshots/jupyter/dns/dns_logs_preview.png)

_Suspicious Queries (Part 1)_  
![Part 1](screenshots/jupyter/dns/dns_rule1_suspicious_queries(1).png)

_Suspicious Queries (Part 2)_  
![Part 2](screenshots/jupyter/dns/dns_rule1_suspicious_queries(2).png)

</details>
</details>

</details>

---

<details>
<summary><strong>Windows Log Detections</strong> — <em>Data Source: windows_logs.csv</em></summary>

| Rule # | Detection Description |
|--------|------------------------|
| 1 | Suspicious parent-child process execution |
| 2 | Repeated failed logins (Event ID 4625) |
| 3 | Privilege escalation attempts (Event ID 4672) |

<details>
<summary>Rule 1 – Suspicious Parent-Child Process Execution</summary>

**Analyst Note:**  
This rule was inspired by real-world phishing cases where Word or Explorer silently launches PowerShell. Since my log data didn’t have a built-in parent process field, I simulated it — then filtered for dangerous child processes coming from apps that normally shouldn’t launch them. This helped me practise detecting LOLBins and post-exploitation behaviour.

**Framework Reference:**  
- **MITRE ATT&CK T1059** – Command and Scripting Interpreter  
- **NIST CSF DE.AE-2**, **NIST 800-61 Step 2.2** – Monitor for suspicious process chains  
- **CIS Control 8.7** – Alert on unexpected command-line activity

**Logic Summary:**
- Simulate `parent_process` column  
- Match suspicious child processes (PowerShell, CertUtil, etc.)  
- Filter for trusted parent apps like `explorer.exe` and `winword.exe`

<details>
<summary>View Windows Rule 1 Screenshots</summary>

_Preview of Raw Windows Logs_  
![Preview](screenshots/jupyter/windows/windows_logs_preview.png)

_Detection Logic_  
![Logic](screenshots/jupyter/windows/windows_rule1_logic.png)

_Detection Output_  
![Output](screenshots/jupyter/windows/windows_rule1_output.png)

</details>
</details>

<details>
<summary>Rule 2 – Repeated Failed Logins from Same Host</summary>

**Analyst Note:**  
I built this rule to simulate brute-force detection using Event ID 4625. I tested different time windows and landed on 2 minutes as a balance between catching bad behaviour and avoiding alert fatigue. It was a good exercise in grouping, timestamp filtering, and simulating correlation logic you’d expect in a real SIEM.

**Framework Reference:**  
- **MITRE ATT&CK T1110.001** – Password Guessing  
- **NIST CSF DE.AE-1**, **CIS Control 16.11** – Detect repeated login failures

**Logic Summary:**
- Filter for Event ID 4625  
- Group by `host` and sort by timestamp  
- Alert if 5+ failed logins occur within 2 minutes

<details>
<summary>View Windows Rule 2 Screenshots</summary>

_Detection Logic_  
![Logic](screenshots/jupyter/windows/windows_rule2_failed_logins_logic.png)

_Detection Output_  
![Output](screenshots/jupyter/windows/windows_rule2_failed_logins_output.png)

</details>
</details>

<details>
<summary>Rule 3 – Privilege Escalation Detection (Event ID 4672)</summary>

**Analyst Note:**  
I wanted this rule to catch unexpected use of high privileges — something often overlooked until it’s too late. By flagging Event ID 4672 from usernames or systems that shouldn’t have admin access, this detection simulates how a SOC might spot lateral movement or privilege misuse in a post-compromise scenario.

**Framework Reference:**  
- **MITRE ATT&CK T1078.003** – Valid Accounts: Local Accounts  
- **NIST 800-61 Step 2.3**, **CIS Control 4.8** – Detect unusual privileged account usage

**Logic Summary:**
- Filter for Event ID 4672  
- Flag suspicious usernames (e.g. guest, test) or hosts (e.g. HR-PC, FINANCE-LAPTOP)  
- Output key metadata for investigation

<details>
<summary>View Windows Rule 3 Screenshots</summary>

_Detection Logic_  
![Logic](screenshots/jupyter/windows/windows_rule3_privilege_escalation_logic.png)

_Detection Output_  
![Output](screenshots/jupyter/windows/windows_rule3_privilege_escalation_output.png)

</details>
</details>

</details>

---

<details>
<summary><strong>Authentication Log Detections</strong> — <em>Data Source: auth_logs.csv</em></summary>

| Rule # | Detection Description |
|--------|------------------------|
| 1 | 5+ failed logins from same IP within 60 seconds |
| 2 | 5+ unique usernames attempted from same IP within 60 seconds |
| 3 | Successful login after multiple failures from same IP in 10 minutes |

<details>
<summary>Rule 1 – Brute-Force Login Detection</summary>

**Analyst Note:**  
This was the first detection I built in this series, and I wanted it to be simple but SOC-relevant. I grouped failed logins by IP and time window, using logic similar to what you’d expect in Splunk or Sentinel. It was important to make this rule sensitive enough to catch attacks, but not trigger on normal failed attempts.

**Framework Reference:**  
- **MITRE ATT&CK T1110.001** – Brute Force  
- **NIST CSF DE.AE-3**, **CIS Control 16.11**

**Logic Summary:**
- Filter for 'FAIL' logins  
- Group by IP and sort by time  
- Trigger alert if 5+ failed attempts in 60 seconds

**Screenshot:**  
_Add screenshot: `auth_rule1_bruteforce_output.png`_

</details>

<details>
<summary>Rule 2 – Password Spraying Detection</summary>

**Analyst Note:**  
This rule helps catch horizontal attacks where attackers cycle through many usernames. Instead of failed logins from one account, I flipped the logic to count distinct usernames. It’s a good example of spotting pattern abuse that’s intentionally quiet.

**Framework Reference:**  
- **MITRE ATT&CK T1110.003** – Password Spraying  
- **CIS Control 16.12** – Detect excessive username attempts

**Logic Summary:**
- Count unique usernames per IP  
- Trigger alert if 5+ usernames in under 60 seconds

**Screenshot:**  
_Add screenshot: `auth_rule2_passwordspray_output.png`_

</details>

<details>
<summary>Rule 3 – Success After Failures</summary>

**Analyst Note:**  
This was the most interesting rule to build. It mimics the real scenario where attackers get in *after* repeated failures. I used a time window of 10 minutes and correlated successes with previous fails — a pattern often missed unless you're doing proper log correlation.

**Framework Reference:**  
- **MITRE ATT&CK T1078.004** – Valid Accounts: Cloud Accounts  
- **NIST SP 800-61 Step 2.4**, **CIS Control 16.13**

**Logic Summary:**
- Look for successful logins  
- Check if they follow ≥3 failures from the same IP within 10 minutes  
- Flag for escalation or deeper triage

**Screenshot:**  
_Add screenshot: `auth_rule3_success_after_fail.png`_

</details>

</details>


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
