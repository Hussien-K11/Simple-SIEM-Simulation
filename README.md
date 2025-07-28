
---

## Phase 1 – Python-Based Detection Logic (COMPLETE)

Built using Jupyter Notebooks to simulate detection logic for SOC environments.

**Data Source:** `auth_logs.csv`  
**Log Fields:** timestamp, username, source_ip, status, location

### Implemented Detections:
| Rule # | Detection Description |
|--------|------------------------|
| 1 | 5 failed logins from same IP in 60 seconds (brute-force) |
| 2 | 5+ unique usernames attempted from same IP in 60 seconds (password spraying) |
| 3 | Successful login after multiple recent failures from same IP (post-spray success) |

> **Analyst Note:**  
> These rules were designed to mimic Tier 1 SOC workflows and demonstrate my ability to think like a detection engineer, even before using Splunk.

---

##  Phase 2 – Splunk Cloud SIEM (IN PROGRESS)

Planned steps:
- [ ] Upload simulated logs to Splunk Cloud Trial
- [ ] Rebuild detections using SPL (Search Processing Language)
- [ ] Simulate alert triage in Splunk (screenshots)
- [ ] Add summary of findings to this README

---

##  Future Enhancements (Optional)
- Add Windows Event Logs (e.g. Event ID 4625, suspicious processes)
- Add DNS logs with rare TLDs or malware C2 domains
- Export alerts as JSON
- Build a minimal alert triage dashboard in Splunk

---

##  Skills Demonstrated
- Detection engineering logic (brute-force, spray, login anomaly)
- Python (pandas, datetime, filtering)
- Log parsing, normalization, and alert simulation
- Jupyter + Splunk (tool versatility)
- Documentation for technical storytelling

---

##  Final Reflection (To be added at project completion)

---

##  Screenshots
*Coming soon in `screenshots/` directory...*

---

##  Lets Connect 
**Hussien Kofi** 
SOC Analyst | Threat-Informed | Detection-Focused  
 
🔗  [LinkedIn](https://www.linkedin.com/in/hussien-kofi-99a012330/)  
💼  [GitHub: Hussien-K11](https://github.com/Hussien-K11)
📧  [Hussienkofi@gmail.com](mailto:Hussienkofi@gmail.com)  

**This project is part of a practical cybersecurity portfolio focused on entry-level SOC analyst skills — including detection logic development, log analysis, and SIEM-based alert triage using Python and Splunk Cloud.**
