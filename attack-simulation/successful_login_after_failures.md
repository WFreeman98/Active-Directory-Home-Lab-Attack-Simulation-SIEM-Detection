# successful login after failures detection

Description: Detecting repeated failed RDP logons followed by a successful logon from the same source IP and user

# ✅ Successful Login After Failures Detection

<div align="center">

![Log Source](https://img.shields.io/badge/Log%20Source-Windows%20Security-blue)
![Event IDs](https://img.shields.io/badge/Event%20IDs-4625%20%7C%204624-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![MITRE](https://img.shields.io/badge/MITRE-T1110%20%7C%20T1078%20%7C%20T1021.001-red)
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

This detection identifies repeated failed RDP logons followed by a successful logon from the same source IP and same user. This is more serious than failed logons alone because it may indicate that a password was guessed or valid credentials were used. I tested this by generating failed RDP attempts from Kali against `bwaltz`, then completing a successful RDP login from the same Kali machine.

---

## 🧪 Test Details

| Field           | Details                                      |
| --------------- | -------------------------------------------- |
| Target Host     | `Target-PC`                                  |
| Domain          | `CORP`                                       |
| User Tested     | `bwaltz`                                     |
| Source IP       | `192.168.10.250`                             |
| Attacker System | Kali Linux                                   |
| Log Source      | Windows Security logs                        |
| SIEM            | Splunk                                       |
| Index           | `endpoint`                                   |
| Event IDs       | `4625` failed logon, `4624` successful logon |

---

## 🧭 MITRE ATT&CK Mapping

| Tactic                        | Technique                         | Reason                                                             |
| ----------------------------- | --------------------------------- | ------------------------------------------------------------------ |
| Credential Access             | T1110 Brute Force                 | Repeated failed logons were generated against the same domain user |
| Defense Evasion / Persistence | T1078 Valid Accounts              | A successful logon happened after the failed attempts              |
| Lateral Movement              | T1021.001 Remote Desktop Protocol | Authentication activity was tied to RDP access                     |

---

## 🔎 Splunk Search

```spl
index=endpoint host="Target-PC" (EventCode=4625 OR EventCode=4624) (TargetUserName="bwaltz" OR Account_Name="bwaltz")
| where Source_Network_Address="192.168.10.250"
| eval user=coalesce(TargetUserName, Account_Name)
| eval failure_time=if(EventCode=4625,_time,null())
| eval success_time=if(EventCode=4624,_time,null())
| stats count(eval(EventCode=4625)) as failure_count count(eval(EventCode=4624)) as success_count earliest(failure_time) as first_failure latest(failure_time) as last_failure earliest(success_time) as first_success values(Logon_Type) as logon_types by Source_Network_Address user host ComputerName
| where failure_count >= 5 AND success_count >= 1 AND first_success > first_failure
| convert ctime(first_failure) ctime(last_failure) ctime(first_success)
| sort -failure_count
```

---

## ⚔️ Attack Simulation

Failed RDP attempts were generated from Kali using Hydra.

```bash
hydra -l bwaltz -P passwords_wrong.txt rdp://192.168.10.100 -V -t 1
```

After the failed attempts, I made a successful RDP login from the same Kali machine.

```bash
xfreerdp /v:192.168.10.100 /d:CORP /u:bwaltz /cert:ignore
```

The working password was not included in the documentation.

---

## 🕵️ Analyst Review

The search showed repeated failed logons for `bwaltz` from `192.168.10.250`, followed by successful logon activity for the same user and source IP. The failed attempts appeared as `Logon Type 3`, and the successful RDP session appeared as `Logon Type 10`.

This matters because a normal brute force alert only proves that authentication failed. When a successful login happens after the failures, the investigation should shift from attempted access to possible account compromise.

### Follow-Up Search

```spl
index=endpoint host="Target-PC" EventCode=4624
| search Source_Network_Address="192.168.10.250"
| table _time host ComputerName Account_Name TargetUserName Source_Network_Address Logon_Type
| sort -_time
```

---

## 🚦 Severity

| Severity | Reason                                                                                                        |
| -------- | ------------------------------------------------------------------------------------------------------------- |
| High     | Same source IP had repeated failed logons and later authenticated successfully as the same user               |
| Medium   | Keep as medium only if the activity is confirmed as normal user behavior                                      |
| High     | Treat as high if the source IP is unusual, the login is unexpected, or suspicious post-login activity appears |

---

## ⚠️ False Positives

| Possible Cause    | Notes                                                             |
| ----------------- | ----------------------------------------------------------------- |
| User error        | User typed the wrong password several times and then got it right |
| Help desk testing | Admin or support testing authentication                           |
| Old credentials   | Saved RDP credentials were outdated and then corrected            |
| Password change   | User recently changed their password                              |
| Lab testing       | Expected activity from this detection test                        |

---

## 📸 Validation Evidence

### Hydra Failed RDP Attempts from Kali

<img width="624" height="457" alt="02_hydra_failures" src="https://github.com/user-attachments/assets/4a5c1002-a465-4011-97af-fb280d5619c6" />

### Raw Splunk Timeline Showing 4625 Failures Followed by 4624 Success

<img width="624" height="299" alt="02_raw_4625_4624_events" src="https://github.com/user-attachments/assets/6525d5ea-80a1-422f-92be-101a6c202894" />

### Splunk Correlation Showing Successful Login After Failures

<img width="624" height="246" alt="02_successful_login_after_failures_detection" src="https://github.com/user-attachments/assets/f797905a-b5db-4f0c-b16c-ba6c8dfb8d95" />

---

## ✅ Conclusion

This detection successfully identified repeated failed RDP logons followed by a successful login for `bwaltz` from `192.168.10.250`. From an analyst perspective, this is the point where failed logon activity becomes more serious because the attacker may have guessed the password or used valid credentials. The next step would be to review post-login activity on `Target-PC`, including PowerShell execution, new services, scheduled tasks, account creation, and group changes.
