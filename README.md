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

---

### Rule 1 – Suspicious Parent-Child Process Execution  
Phishing payloads often abuse trusted parent apps like Word or Explorer to silently spawn PowerShell or CertUtil. This detection highlights that relationship and flags it early, before the attack progresses.

<details>
<summary>See how this rule works, why it matters, and what it looks like in action</summary>

**Analyst Note:**  
This rule was inspired by phishing incidents where Word or Explorer silently launches PowerShell. Since my logs didn’t include a `parent_process` field, I simulated one and filtered for suspicious child processes launched by trusted applications. This helped me practise detecting post-exploitation activity by analysing process lineage.

**Framework Reference:**  
- **MITRE ATT&CK T1059** – Command and Scripting Interpreter  
- **NIST CSF DE.AE-2**, **NIST 800-61 Step 2.2** – Monitor suspicious process chains  
- **CIS Control 8.7** – Unexpected command-line execution

**Logic Summary:**
- Simulate `parent_process` field  
- Flag suspicious child processes such as PowerShell or CertUtil  
- Detect when trusted apps like `explorer.exe` launch them

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

---

### Rule 2 – Repeated Failed Logins from Same Host  
This rule simulates a brute-force attack by identifying five or more failed login attempts from the same host within two minutes. It captures suspicious behaviour that may go undetected without event correlation.

<details>
<summary>See how this rule works, why it matters, and what it looks like in action</summary>

**Analyst Note:**  
I created this rule to simulate brute-force login patterns. After testing different thresholds, I selected a two-minute window to balance effectiveness and reduce false positives. This rule helped me practise grouping events by time and source, which is key to writing meaningful detections.

**Framework Reference:**  
- **MITRE ATT&CK T1110.001** – Password Guessing  
- **NIST CSF DE.AE-1**, **CIS Control 16.11** – Detect repeated login failures

**Logic Summary:**
- Filter for Event ID 4625  
- Group by `host` and sort by time  
- Trigger an alert when five or more failures occur within two minutes

<details>
<summary>View Windows Rule 2 Screenshots</summary>

_Detection Logic_  
![Logic](screenshots/jupyter/windows/windows_rule2_failed_logins_logic.png)

_Detection Output_  
![Output](screenshots/jupyter/windows/windows_rule2_failed_logins_output.png)

</details>
</details>

---

### Rule 3 – Privilege Escalation Detection (Event ID 4672)  
This rule flags when high-level privileges are assigned to low-trust accounts or machines. It highlights potential lateral movement or misuse after initial access.

<details>
<summary>See how this rule works, why it matters, and what it looks like in action</summary>

**Analyst Note:**  
Privilege escalation is a major concern during an attack. I designed this rule to detect Event ID 4672 being triggered by accounts like `guest` or `test`, or by endpoints that are not usually involved in administrative activity. It was useful for learning how to model post-compromise scenarios based on endpoint and identity context.

**Framework Reference:**  
- **MITRE ATT&CK T1078.003** – Valid Accounts: Local Accounts  
- **NIST 800-61 Step 2.3**, **CIS Control 4.8** – Detect unusual privileged access

**Logic Summary:**
- Filter for Event ID 4672  
- Flag events where users or hosts appear suspicious  
- Display key metadata like username, host, and assigned privileges

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
