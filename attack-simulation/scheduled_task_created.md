# scheduled task created detection

Description: Detecting scheduled task creation using Windows Security and Sysmon logs

# ⏰ Scheduled Task Created Detection

<div align="center">

![Log Source](https://img.shields.io/badge/Log%20Source-Windows%20Security%20%7C%20Sysmon-blue)
![Event IDs](https://img.shields.io/badge/Event%20IDs-4698%20%7C%201-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![MITRE](https://img.shields.io/badge/MITRE-T1053.005-red)
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

This detection identifies scheduled task creation on a Windows endpoint. I tested it on `Target-PC` by creating a harmless scheduled task with `schtasks.exe` and validating the activity in Splunk. The goal was to confirm visibility into both the scheduled task event and the process that created it.

---

## 🧪 Lab Details

| Field            | Details                              |
| ---------------- | ------------------------------------ |
| Host             | `Target-PC`                          |
| SIEM             | Splunk                               |
| Log Sources      | Windows Security and Sysmon          |
| Windows Event ID | `4698`                               |
| Sysmon Event ID  | `1`                                  |
| Tool Used        | `schtasks.exe`                       |
| Task Name        | `\Maintenance\Endpoint-Health-Check` |
| Splunk Index     | `endpoint`                           |

---

## 🧭 MITRE ATT&CK Mapping

| Tactic      | Technique                | Reason                                         |
| ----------- | ------------------------ | ---------------------------------------------- |
| Persistence | T1053.005 Scheduled Task | Scheduled tasks can be used to maintain access |
| Execution   | T1053.005 Scheduled Task | Scheduled tasks can run commands or scripts    |

---

## 🔎 Splunk Search

```spl
index=endpoint host="Target-PC" ("Endpoint-Health-Check" OR "schtasks")
| table _time EventCode EventID host ComputerName source Image CommandLine TaskName Message _raw
| sort -_time
```

### Windows Security Search

```spl
index=endpoint host="Target-PC" EventCode=4698
| table _time EventCode host ComputerName Account_Name TaskName Message _raw
| sort -_time
```

### Sysmon Process Search

```spl
index=endpoint host="Target-PC" source="*Sysmon*" EventCode=1 "schtasks"
| table _time EventCode EventID host ComputerName Image CommandLine ParentImage User
| sort -_time
```

---

## ⚔️ Simulation

A harmless scheduled task was created on `Target-PC` using `schtasks.exe`.

```cmd
schtasks /create /tn "\Maintenance\Endpoint-Health-Check" /tr "cmd.exe /c echo Endpoint health check completed > C:\Windows\Temp\endpoint_health_check.txt" /sc once /st 23:59 /f
```

Cleanup command:

```cmd
schtasks /delete /tn "\Maintenance\Endpoint-Health-Check" /f
```

The task only wrote a simple text file and was used to generate detection telemetry.

---

## 🕵️ Analyst Review

Splunk returned scheduled task creation evidence from `Target-PC`. Windows Security Event ID `4698` confirmed that a scheduled task was created, and Sysmon Event ID `1` showed `schtasks.exe` process creation with the command line.

The task name alone does not prove malicious activity. The most important part is the task action, trigger, user context, parent process, and file path. In a real investigation, I would check whether the task runs PowerShell, `cmd.exe`, scripts, or executables from user-writable folders like Temp, Downloads, or AppData.

---

## 🚦 Severity

| Severity | Condition                                                                          |
| -------- | ---------------------------------------------------------------------------------- |
| Medium   | Scheduled task is created                                                          |
| High     | Task runs PowerShell, cmd, or suspicious scripts                                   |
| High     | Task executes from Temp, Downloads, or AppData                                     |
| High     | Task runs at logon or startup                                                      |
| High     | Task appears after suspicious logon, download, Defender tampering, or LSASS access |

---

## ⚠️ False Positives

| Possible Cause              | Notes                                      |
| --------------------------- | ------------------------------------------ |
| Admin automation            | Normal IT maintenance                      |
| Software deployment         | Approved endpoint management activity      |
| Patch management            | Scheduled update tasks                     |
| Backup or monitoring agents | Expected system tasks                      |
| Lab testing                 | Expected activity from this detection test |

---

## 📸 Validation Evidence

### Scheduled Task Creation Command and Query Confirmation

<img width="624" height="158" alt="11_schtasks_creation_command" src="https://github.com/user-attachments/assets/726dd9e0-f1ea-4054-9186-5b385863252e" />

### Windows Security Event ID 4698 Showing Scheduled Task Creation

<img width="624" height="387" alt="11_raw_4698_scheduled_task_created" src="https://github.com/user-attachments/assets/79835ffb-d701-40ac-a69e-75ee0a359702" />

### Sysmon Event ID 1 Showing schtasks.exe Process Creation

<img width="624" height="238" alt="11_scheduled_task_detection" src="https://github.com/user-attachments/assets/1228d70b-fc5d-49f2-afbe-bfacebbbece8" />

---

## ✅ Conclusion

This detection confirmed scheduled task creation activity on `Target-PC` using Windows Security Event ID `4698` and Sysmon Event ID `1`. The lab task was harmless, but the detection is useful because scheduled tasks are commonly reviewed for persistence and execution. In a real SOC investigation, I would review the task action, trigger, user, parent process, command line, and surrounding endpoint activity.
