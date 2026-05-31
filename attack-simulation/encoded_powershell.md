# encoded powershell detection

Description: Detecting PowerShell execution with encoded command arguments using Sysmon Event ID 1

# ⚡ Encoded PowerShell Detection

<div align="center">

![Log Source](https://img.shields.io/badge/Log%20Source-Sysmon-blue)
![Event ID](https://img.shields.io/badge/Event%20ID-1-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![MITRE](https://img.shields.io/badge/MITRE-T1059.001%20%7C%20T1027-red)
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

This detection identifies PowerShell running with encoded command arguments. I tested it on `Target-PC` using a safe encoded PowerShell command and validated the process creation event in Splunk. The goal was to confirm that Sysmon Event ID `1` captured the PowerShell execution and command line.

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

| Tactic          | Technique                             | Reason                                   |
| --------------- | ------------------------------------- | ---------------------------------------- |
| Execution       | T1059.001 PowerShell                  | PowerShell was used to execute a command |
| Defense Evasion | T1027 Obfuscated Files or Information | The command content was Base64 encoded   |

---

## 🔎 Splunk Search

```spl
index=endpoint host="Target-PC" ("EncodedCommand" OR "-EncodedCommand" OR " -enc ")
| table _time host ComputerName source EventCode EventID Image ParentImage CommandLine User
| sort -_time
```

---

## ⚔️ Simulation

A safe encoded PowerShell command was executed on `Target-PC`.

```powershell
$cmd = 'Write-Output "SOC Lab Encoded PowerShell Test"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -NoProfile -EncodedCommand $encoded
```

Expected output:

```text
SOC Lab Encoded PowerShell Test
```

This command was safe and only used to generate Sysmon telemetry for the lab.

---

## 🕵️ Analyst Review

Encoded PowerShell is not always malicious, but it should be reviewed because attackers often use it to hide command content. In this lab, Splunk returned a Sysmon Event ID `1` process creation event showing `powershell.exe` running with `-EncodedCommand`.

The main follow-up is to decode the payload and review what the command actually did. I would also check the parent process, user context, network connections, file creation, and any child processes launched by PowerShell.

---

## 🚦 Severity

| Severity | Condition                                                              |
| -------- | ---------------------------------------------------------------------- |
| Medium   | Encoded PowerShell is observed                                         |
| High     | PowerShell is launched by Office, a browser, or an unknown process     |
| High     | Decoded command downloads remote content                               |
| High     | Command disables Defender, creates persistence, or touches credentials |
| High     | Suspicious network or child process activity follows execution         |

---

## ⚠️ False Positives

| Possible Cause      | Notes                                      |
| ------------------- | ------------------------------------------ |
| Admin scripts       | Approved PowerShell automation             |
| Software deployment | Endpoint management tools                  |
| Security testing    | Authorized testing activity                |
| Automation jobs     | Scheduled or scripted tasks                |
| Lab testing         | Expected activity from this detection test |

---

## 📸 Validation Evidence

### Safe Encoded PowerShell Command Executed on Target-PC

<img width="624" height="125" alt="06_encoded_powershell_execution" src="https://github.com/user-attachments/assets/22cad9dc-9483-4dab-ac94-087b1fa61372" />

### Raw Sysmon Event ID 1 Showing Encoded PowerShell Activity

<img width="624" height="167" alt="06_raw_sysmon_eventid1_encoded_powershell" src="https://github.com/user-attachments/assets/8062e3dd-b649-4722-9124-bd65545d5ff6" />

### Splunk Detection Showing EncodedCommand Execution

<img width="624" height="170" alt="06_encoded_powershell_detection" src="https://github.com/user-attachments/assets/1797a798-9b2d-4b5a-8a74-182e575e0147" />

---

## ✅ Conclusion

This detection confirmed encoded PowerShell execution on `Target-PC` using Sysmon Event ID `1`. The command used in the lab was safe, but the detection is valuable because encoded PowerShell can hide the real command being executed. In a real investigation, I would decode the payload, review the parent process, and check for network connections, file creation, child processes, or other suspicious activity after execution.

