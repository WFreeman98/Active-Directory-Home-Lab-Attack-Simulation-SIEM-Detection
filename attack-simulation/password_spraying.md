# password spraying detection

Description: Detecting one source IP generating failed logons against multiple Windows domain accounts

# 🔐 Password Spraying Detection

<div align="center">

![Log Source](https://img.shields.io/badge/Log%20Source-Windows%20Security-blue)
![Event ID](https://img.shields.io/badge/Event%20ID-4625-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![MITRE](https://img.shields.io/badge/MITRE-T1110.003%20%7C%20T1021.001-red)
![Status](https://img.shields.io/badge/Status-Validated-brightgreen)

</div>

---

## 📋 Table of Contents

* [Detection Summary](#-detection-summary)
* [Test Details](#-test-details)
* [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
* [Splunk Search](#-splunk-search)
* [Attack Simulation](#-attack-simulation)
* [Analyst Review](#-analyst-review)
* [Severity](#-severity)
* [False Positives](#-false-positives)
* [Validation Evidence](#-validation-evidence)
* [Conclusion](#-conclusion)

---

## 🎯 Detection Summary

This detection identifies password spraying activity against multiple Windows domain user accounts. I tested it by using Kali to attempt one incorrect password against several domain users on `Target-PC`. The main signal is one source IP generating failed logons against multiple accounts, not just repeated failures against one user.

---

## 🧪 Test Details

| Field      | Details          |
| ---------- | ---------------- |
| Attacker   | Kali Linux       |
| Target     | `Target-PC`      |
| Domain     | `corp.local`     |
| Source IP  | `192.168.10.250` |
| Log Source | Windows Security |
| Event ID   | `4625`           |
| Logon Type | `3`              |
| SIEM       | Splunk           |
| Index      | `endpoint`       |

---

## 🧭 MITRE ATT&CK Mapping

| Tactic            | Technique                         | Reason                                                      |
| ----------------- | --------------------------------- | ----------------------------------------------------------- |
| Credential Access | T1110.003 Password Spraying       | One password was attempted against multiple domain accounts |
| Lateral Movement  | T1021.001 Remote Desktop Protocol | The authentication attempts targeted RDP                    |

---

## 🔎 Splunk Search

```spl
index=endpoint host="Target-PC" EventCode=4625
| eval source_ip=coalesce(Source_Network_Address, IpAddress, Workstation_Name)
| eval user=lower(coalesce(TargetUserName, Account_Name))
| where source_ip="192.168.10.250"
| stats count as failure_count dc(user) as unique_users values(user) as targeted_users values(Logon_Type) as logon_types by source_ip host ComputerName
| where unique_users >= 3 AND failure_count >= 3
| sort -unique_users
```

---

## ⚔️ Attack Simulation

Hydra was used from Kali to attempt one incorrect password across multiple users.

```bash
hydra -L spray_users.txt -p 'Kali2026' rdp://192.168.10.100 -V -t 1
```

The password was intentionally wrong. The goal was to generate failed authentication logs and validate the detection in Splunk.

---

## 🕵️ Analyst Review

Password spraying is different from normal brute forcing. A brute force attack usually tries many passwords against one account, while password spraying tries one password against many accounts.

The unique user count is the main signal in this detection. If any targeted user later has a successful Event ID `4624` logon, the alert should be treated as possible account compromise.

### Follow-Up Search

```spl
index=endpoint host="Target-PC" (EventCode=4625 OR EventCode=4624)
| eval source_ip=coalesce(Source_Network_Address, IpAddress, Workstation_Name)
| eval user=lower(coalesce(TargetUserName, Account_Name))
| where source_ip="192.168.10.250"
| table _time EventCode source_ip user host ComputerName Logon_Type Failure_Reason
| sort _time
```

---

## 🚦 Severity

| Severity | Condition                                                        |
| -------- | ---------------------------------------------------------------- |
| Medium   | One source IP targets multiple users with failed logons          |
| High     | A targeted user has a successful Event ID `4624` after the spray |
| High     | Same source IP targets multiple systems                          |
| High     | Follow-on activity appears after authentication                  |

---

## ⚠️ False Positives

| Possible Cause          | Notes                                        |
| ----------------------- | -------------------------------------------- |
| Help desk testing       | Admin or support authentication testing      |
| User onboarding         | Multiple accounts tested during setup        |
| Misconfigured scripts   | Script attempts old or incorrect credentials |
| Password policy testing | Approved internal testing                    |
| Lab testing             | Expected activity from this detection test   |

---

## 📸 Validation Evidence

### Hydra Password Spray from Kali

<img width="624" height="282" alt="03_hydra_password_spray" src="https://github.com/user-attachments/assets/28bbfe5e-93c8-4509-833b-9c27e2045602" />

### Raw Event ID 4625 Failed Logons Against Multiple Users

<img width="624" height="308" alt="03_raw_4625_multiple_users" src="https://github.com/user-attachments/assets/07cdf712-0470-4a37-b2ce-0b11b01511b3" />

### Splunk Detection Showing Multiple Targeted Users From One Source IP

<img width="624" height="255" alt="03_password_spraying_detection" src="https://github.com/user-attachments/assets/45af8170-bd86-41c6-be2e-1f5ba94a260a" />

---

## ✅ Conclusion

This detection validated password spraying behavior in the lab. Hydra attempted one incorrect password across multiple domain accounts, and `Target-PC` generated Windows Security Event ID `4625` failed logons from the Kali source IP. The most important next step is to check for successful Event ID `4624` logons after the failed attempts.
