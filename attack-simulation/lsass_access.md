# lsass access detection

Description: Detecting suspicious access to lsass.exe using Sysmon ProcessAccess telemetry

# 🧠 LSASS Access Detection

<div align="center">

![Log Source](https://img.shields.io/badge/Log%20Source-Sysmon-blue)
![Event ID](https://img.shields.io/badge/Event%20ID-10-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![MITRE](https://img.shields.io/badge/MITRE-T1003.001-red)
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

This detection identifies process access to `lsass.exe` using Sysmon Event ID `10`. I tested it on `Target-PC` by safely opening a handle to LSASS with PowerShell and validating the ProcessAccess event in Splunk. The goal was to confirm visibility into LSASS access behavior without dumping credentials or saving credential material.

---

## 🧪 Lab Details

| Field          | Details          |
| -------------- | ---------------- |
| Host           | `Target-PC`      |
| SIEM           | Splunk           |
| Log Source     | Sysmon           |
| Event ID       | `10`             |
| Target Process | `lsass.exe`      |
| Source Process | `powershell.exe` |
| Splunk Index   | `endpoint`       |

---

## 🧭 MITRE ATT&CK Mapping

| Tactic            | Technique              | Reason                                                |
| ----------------- | ---------------------- | ----------------------------------------------------- |
| Credential Access | T1003.001 LSASS Memory | LSASS access can indicate credential dumping behavior |

---

## 🔎 Splunk Search

```spl
index=endpoint host="Target-PC" source="*Sysmon*" EventCode=10
| search TargetImage="*lsass.exe"
| table _time host ComputerName User SourceImage TargetImage GrantedAccess CallTrace
| sort -_time
```

---

## ⚔️ Simulation

A safe LSASS access simulation was performed on `Target-PC` using PowerShell.

```powershell
$p = [System.Diagnostics.Process]::GetProcessesByName("lsass")[0]
$p.Handle
```

This opened a handle to the LSASS process and generated Sysmon Event ID `10`. This test did not dump LSASS memory, run Mimikatz, create a dump file, or extract credentials.

---

## 🕵️ Analyst Review

LSASS access is high risk because attackers often target LSASS memory to steal credentials. In this lab, PowerShell accessed `lsass.exe`, and Splunk captured the behavior through Sysmon ProcessAccess telemetry.

The main investigation points are the source process, user context, `GrantedAccess` value, `CallTrace`, and surrounding activity. In a real investigation, I would check whether a dump file was created, whether the source process was unusual, and whether the activity happened after suspicious logon activity.

---

## 🚦 Severity

| Severity | Condition                                                      |
| -------- | -------------------------------------------------------------- |
| High     | PowerShell or another unusual process accesses LSASS           |
| High     | Credential dumping tool accesses LSASS                         |
| High     | Dump file is created after LSASS access                        |
| High     | Source process runs from Temp, Downloads, or AppData           |
| High     | Activity follows suspicious logon or privilege change activity |

---

## ⚠️ False Positives

| Possible Cause        | Notes                                            |
| --------------------- | ------------------------------------------------ |
| Antivirus tools       | Security products may access LSASS               |
| EDR tools             | Monitoring tools may inspect LSASS               |
| Backup tools          | Some trusted tools may touch sensitive processes |
| Admin troubleshooting | Administrator investigation or testing           |
| Lab testing           | Expected activity from this detection test       |

---

## 📸 Validation Evidence

### Safe PowerShell LSASS Access Simulation

<img width="624" height="40" alt="08_safe_lsass_access_simulation" src="https://github.com/user-attachments/assets/166816e9-365d-49d6-a40c-b0bdfcecca42" />

### Raw Sysmon Event ID 10 Showing ProcessAccess to LSASS

<img width="624" height="262" alt="08_raw_sysmon_eventid10_lsass_access" src="https://github.com/user-attachments/assets/1982257e-534f-4c9e-982a-2e75fad0b5af" />

### Splunk Detection Showing LSASS Access Behavior

<img width="624" height="40" alt="08_safe_lsass_access_simulation" src="https://github.com/user-attachments/assets/beea1e96-f2fd-4ca3-8f34-da5a4af1ff0c" />

---

## ✅ Conclusion

This detection confirmed process access to `lsass.exe` on `Target-PC` using Sysmon Event ID `10`. The lab simulation was safe and did not dump credentials, but the behavior is important because LSASS access is commonly reviewed during credential dumping investigations. In a real SOC investigation, I would review the source process, user context, `GrantedAccess`, `CallTrace`, dump file creation, recent logons, and any follow-on activity that could indicate credential theft or lateral movement.

