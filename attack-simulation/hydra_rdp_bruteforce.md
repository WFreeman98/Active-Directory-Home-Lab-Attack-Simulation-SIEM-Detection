# rdp brute force detection

Description: Detecting repeated failed RDP authentication attempts against a Windows domain workstation

# 🔐 RDP Brute Force Detection

<div align="center">

![Log Source](https://img.shields.io/badge/Log%20Source-Windows%20Security-blue)
![Event ID](https://img.shields.io/badge/Event%20ID-4625-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![MITRE](https://img.shields.io/badge/MITRE-T1110%20%7C%20T1021.001-red)
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
* [False Positives](#-false-positives)
* [Validation Evidence](#-validation-evidence)
* [Conclusion](#-conclusion)

---

## 🎯 Detection Summary

This detection identifies repeated failed RDP authentication attempts against a Windows domain workstation. I tested it by sending failed RDP login attempts from Kali to `Target-PC` and validating the activity in Splunk. The goal was to confirm that Windows Security Event ID `4625` captured the failed authentication attempts and that Splunk could detect the brute force pattern.

---

## 🧪 Test Details

| Field          | Details                          |
| -------------- | -------------------------------- |
| Target Account | `bwaltz`                         |
| Target Host    | `Target-PC`                      |
| Attacker Host  | Kali                             |
| Attacker IP    | `192.168.10.250`                 |
| Target Service | RDP                              |
| Main Event     | Windows Security Event ID `4625` |
| Splunk Index   | `endpoint`                       |

---

## 🧭 MITRE ATT&CK Mapping

| Tactic            | Technique                         | Reason                                              |
| ----------------- | --------------------------------- | --------------------------------------------------- |
| Credential Access | T1110 Brute Force                 | Repeated failed logons against the same domain user |
| Lateral Movement  | T1021.001 Remote Desktop Protocol | Failed authentication attempts targeted RDP         |

---

## 🔎 Splunk Search

```spl
index=endpoint host="Target-PC" EventCode=4625
| eval source_ip=coalesce(Source_Network_Address, IpAddress, Workstation_Name)
| eval user=coalesce(Account_Name, TargetUserName)
| search user="bwaltz"
| where Logon_Type=3 OR Logon_Type=10 OR Logon_Type="3" OR Logon_Type="10"
| stats count earliest(_time) as first_seen latest(_time) as last_seen by source_ip user host ComputerName Logon_Type
| where count >= 5
| convert ctime(first_seen) ctime(last_seen)
| sort -count
```

---

## ⚔️ Attack Simulation

Hydra was used from Kali to generate failed RDP authentication attempts against `Target-PC`.

```bash
hydra -l bwaltz -P passwords_wrong.txt rdp://192.168.10.100 -V
```

The password file only contained incorrect passwords. The goal was to create failed authentication telemetry, not compromise the account.

---

## 🕵️ Analyst Review

The activity showed repeated failed authentication attempts against the same domain user from the same source IP. This is stronger than a single failed login because it shows repeated guessing behavior.

The first follow-up would be to check whether the same user had a successful Event ID `4624` logon after the failed attempts. If a successful logon occurred from the same source IP after the failures, the alert should be treated as possible account compromise.

### Follow-Up Search

```spl
index=endpoint host="Target-PC" (EventCode=4625 OR EventCode=4624)
| eval source_ip=coalesce(Source_Network_Address, IpAddress, Workstation_Name)
| eval user=coalesce(Account_Name, TargetUserName)
| search user="bwaltz"
| table _time EventCode user source_ip host ComputerName Logon_Type
| sort _time
```

---

## ⚠️ False Positives

| Possible Cause   | Notes                                            |
| ---------------- | ------------------------------------------------ |
| User error       | User typed the wrong password several times      |
| Old credentials  | Saved credentials were outdated                  |
| Admin testing    | Administrator was testing authentication         |
| Scanner activity | Vulnerability scanner triggered RDP/NLA failures |
| Lab testing      | Expected activity from this detection test       |

---

## 📸 Validation Evidence

### Hydra Attack from Kali

<img width="500" alt="hydra_attack" src="https://github.com/user-attachments/assets/ed55f93f-fda6-420c-b93b-ca620abec180" />

### Raw Event ID 4625 Failed Logons

<img width="500" alt="raw_4625_events" src="https://github.com/user-attachments/assets/938e1144-c209-477c-9e75-e5e32162fbfd" />

### Splunk Detection Query Result

<img width="500" alt="rdp_bruteforce_detection" src="https://github.com/user-attachments/assets/c0845c17-2ed6-4aef-9ae5-7537ac553b15" />

---

## ✅ Conclusion

This detection successfully identified repeated failed RDP authentication attempts against `bwaltz` on `Target-PC`. The source IP `192.168.10.250` matched the Kali machine used during testing. The most important next step is to search for Event ID `4624` from the same source IP and user to determine whether the brute force attempt was followed by a successful login.

