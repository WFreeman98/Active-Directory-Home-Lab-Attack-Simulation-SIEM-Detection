# defender tampering detection

Description: Detecting Microsoft Defender tampering indicators using Sysmon process creation logs

# 🛡️ Defender Tampering Detection

<div align="center">

![Log Source](https://img.shields.io/badge/Log%20Source-Sysmon-blue)
![Event ID](https://img.shields.io/badge/Event%20ID-1-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![MITRE](https://img.shields.io/badge/MITRE-T1562.001-red)
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

This detection identifies command-line activity that may indicate Microsoft Defender tampering. I tested it on `Target-PC` using a safe PowerShell simulation command and validated the process creation event in Splunk. The goal was to confirm that Sysmon Event ID `1` captured Defender tampering indicators such as `Set-MpPreference` and `DisableRealtimeMonitoring`.

---

## 🧪 Lab Details

| Field        | Details          |
| ------------ | ---------------- |
| Host         | `Target-PC`      |
| SIEM         | Splunk           |
| Log Source   | Sysmon           |
| Event ID     | `1`              |
| Process      | `powershell.exe` |
| Splunk Index | `endpoint`       |

---

## 🧭 MITRE ATT&CK Mapping

| Tactic          | Technique                         | Reason                                                                                     |
| --------------- | --------------------------------- | ------------------------------------------------------------------------------------------ |
| Defense Evasion | T1562.001 Disable or Modify Tools | Attackers may try to disable or weaken Microsoft Defender before running tools or payloads |

---

## 🔎 Splunk Search

```spl
index=endpoint host="Target-PC" source="*Sysmon*" EventCode=1
("DisableRealtimeMonitoring" OR "Set-MpPreference" OR "Add-MpPreference" OR "ExclusionPath" OR "DisableBehaviorMonitoring")
| table _time EventCode host ComputerName Image CommandLine ParentImage User
| sort -_time
```

---

## ⚔️ Simulation

A safe PowerShell command was executed on `Target-PC`.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SIMULATION: Set-MpPreference -DisableRealtimeMonitoring True'"
```

This command only printed text. It did not disable Microsoft Defender, add exclusions, or change security settings.

---

## 🕵️ Analyst Review

Splunk returned a Sysmon Event ID `1` process creation event from `Target-PC`. The command line contained Defender tampering indicators, including `Set-MpPreference` and `DisableRealtimeMonitoring`.

In this lab, the command was only a safe simulation. In a real investigation, I would confirm whether Defender settings actually changed, review the parent process, check the user context, and search for related activity such as downloads, LSASS access, scheduled tasks, new services, or event log clearing.

---

## 🚦 Severity

| Severity | Condition                                            |
| -------- | ---------------------------------------------------- |
| High     | Defender settings were changed                       |
| High     | Exclusions were added                                |
| High     | PowerShell was launched by an unusual parent process |
| High     | Activity happened after a suspicious download        |
| High     | Activity happened before LSASS access or persistence |

---

## ⚠️ False Positives

| Possible Cause           | Notes                                      |
| ------------------------ | ------------------------------------------ |
| Admin testing            | Approved Defender configuration testing    |
| Security team validation | Authorized detection testing               |
| Endpoint management      | Approved management scripts                |
| Troubleshooting          | IT staff investigating Defender settings   |
| Lab testing              | Expected activity from this detection test |

---

## 📸 Validation Evidence

### Safe PowerShell Simulation Command Containing Defender Tampering Indicators

<img width="646" height="82" alt="10_defender_tampering_simulation_command" src="https://github.com/user-attachments/assets/033f8510-d199-4d7d-a278-085421e5f137" />

### Raw Sysmon Event ID 1 Showing PowerShell Command-Line Evidence

<img width="624" height="382" alt="10_raw_ sysmon_eventid1_defender_tampering" src="https://github.com/user-attachments/assets/b2f3fb88-7143-4568-a905-58bb0d3ed6ea" />

### Splunk Detection Query Identifying Defender Tampering Indicators

<img width="624" height="385" alt="10_defender_tampering_detection" src="https://github.com/user-attachments/assets/9e1fea3b-2541-45e4-8aa6-0bb9d4476615" />

---

## ✅ Conclusion

This detection confirmed Defender tampering-style command-line activity on `Target-PC` using Sysmon Event ID `1`. The lab command was safe and did not modify Microsoft Defender, but it validated that Splunk could detect command-line indicators commonly associated with defense evasion. In a real SOC investigation, I would verify whether Defender settings changed, check for exclusions, review the parent process, and search for suspicious activity before and after the event.

The lab command was intentionally safe and did not modify Microsoft Defender. It only generated command-line evidence that looked like Defender tampering so the detection logic could be validated in Splunk.

This detection matters because attackers often try to weaken security tools before running malware, dumping credentials, or creating persistence. In a real SOC investigation, I would not stop at the keyword match. I would confirm whether Defender settings changed, check for exclusions, review the parent process, and search for related activity before and after the event.
