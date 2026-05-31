# event log clearing detection

Description: Detecting Windows Security log clearing using Event ID 1102

# 🧹 Event Log Clearing Detection

<div align="center">

![Log Source](https://img.shields.io/badge/Log%20Source-Windows%20Security-blue)
![Event ID](https://img.shields.io/badge/Event%20ID-1102-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![MITRE](https://img.shields.io/badge/MITRE-T1070.001-red)
![Status](https://img.shields.io/badge/Status-Validated-brightgreen)

</div>

---

## 📋 Table of Contents

* [Detection Summary](#-detection-summary)
* [Lab Details](#-lab-details)
* [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
* [Splunk Search](#-splunk-search)
* [Simulation](#-simulation)
* [Analyst Review](#-analyst-review)
* [Severity](#-severity)
* [False Positives](#-false-positives)
* [Validation Evidence](#-validation-evidence)
* [Conclusion](#-conclusion)

---

## 🎯 Detection Summary

This detection identifies Windows Security log clearing activity using Event ID `1102`. I tested it on `Target-PC` by clearing the Security log with `wevtutil` and validating the event in Splunk. This matters because clearing the Security log can remove evidence of failed logons, successful logons, account changes, privilege changes, and other suspicious activity.

---

## 🧪 Lab Details

| Field        | Details          |
| ------------ | ---------------- |
| Host         | `Target-PC`      |
| SIEM         | Splunk           |
| Log Source   | Windows Security |
| Event ID     | `1102`           |
| Tool Used    | `wevtutil`       |
| Splunk Index | `endpoint`       |

---

## 🧭 MITRE ATT&CK Mapping

| Tactic          | Technique                          | Reason                                           |
| --------------- | ---------------------------------- | ------------------------------------------------ |
| Defense Evasion | T1070.001 Clear Windows Event Logs | Clearing logs can hide earlier attacker activity |

---

## 🔎 Splunk Search

```spl
index=endpoint host="Target-PC" EventCode=1102
| table _time EventCode host ComputerName Account_Name Message
| sort -_time
```

---

## ⚔️ Simulation

The Windows Security log was cleared on `Target-PC` using an administrator command prompt.

```cmd
wevtutil cl Security
```

Confirmation command:

```cmd
echo Security log clear test completed
```

This generated Windows Security Event ID `1102`. Centralized logging in Splunk preserved the evidence even after the local Security log was cleared.

---

## 🕵️ Analyst Review

Splunk showed Event ID `1102` from `Target-PC`, with the message showing that the audit log was cleared. The event showed `Administrator` as the account associated with the clearing activity.

The event itself confirms that the Security log was cleared, but it does not explain why. The most important investigation step is to review what happened before the clearing event. I would look for failed logons, successful remote logons, account creation, privileged group changes, PowerShell activity, scheduled tasks, services, or other activity that may have been hidden.

---

## 🚦 Severity

| Severity | Condition                                                          |
| -------- | ------------------------------------------------------------------ |
| High     | Security log was cleared                                           |
| High     | Event happened after failed or successful remote logons            |
| High     | Event happened after account creation or group changes             |
| High     | Event happened after suspicious PowerShell or persistence activity |
| High     | Account that cleared the log is unusual or unexpected              |

---

## ⚠️ False Positives

| Possible Cause     | Notes                                      |
| ------------------ | ------------------------------------------ |
| Admin maintenance  | Approved troubleshooting or cleanup        |
| Security testing   | Authorized internal testing                |
| Lab testing        | Expected activity from this detection test |
| Approved procedure | Documented log cleanup process             |

---

## 📸 Validation Evidence

### wevtutil Command Clearing the Security Log on Target-PC

<img width="566" height="151" alt="09_wevtutil_clear_security_log" src="https://github.com/user-attachments/assets/cbbfb315-d0df-4063-a97e-afcde1f0d8e1" />

### Raw Windows Event ID 1102 Showing Security Log Cleared

<img width="624" height="342" alt="09_raw_1102_security_log_cleared" src="https://github.com/user-attachments/assets/03281f6c-b854-4dc6-b81b-fab7d499ec8a" />

### Splunk Detection Showing Event ID 1102 Log Clearing Activity

<img width="624" height="181" alt="09_event_log_clearing_detection" src="https://github.com/user-attachments/assets/aac624b3-7bb6-4784-bfa3-045766d045f7" />

---

## ✅ Conclusion

This detection confirmed Windows Security log clearing on `Target-PC` using Event ID `1102`. The lab action was performed with `wevtutil cl Security`, and Splunk captured the event showing that the audit log was cleared. In a real SOC investigation, I would build a timeline before the clearing event and review authentication activity, account changes, PowerShell execution, scheduled tasks, services, and other activity that may have been hidden.
