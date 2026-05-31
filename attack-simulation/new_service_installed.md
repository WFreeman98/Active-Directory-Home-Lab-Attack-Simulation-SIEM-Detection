# new service installed detection

Description: Detecting new Windows service installation using Windows System and Sysmon logs

# ⚙️ New Service Installed Detection

<div align="center">

![Log Source](https://img.shields.io/badge/Log%20Source-Windows%20System%20%7C%20Sysmon-blue)
![Event IDs](https://img.shields.io/badge/Event%20IDs-7045%20%7C%201-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![MITRE](https://img.shields.io/badge/MITRE-T1543.003-red)
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

This detection identifies new Windows service installation activity on a Windows endpoint. I tested it on `Target-PC` by creating a harmless service with `sc.exe` and validating the activity in Splunk. The goal was to confirm visibility into both the service installation event and the process that created it.

---

## 🧪 Lab Details

| Field            | Details                   |
| ---------------- | ------------------------- |
| Host             | `Target-PC`               |
| SIEM             | Splunk                    |
| Log Sources      | Windows System and Sysmon |
| Windows Event ID | `7045`                    |
| Sysmon Event ID  | `1`                       |
| Tool Used        | `sc.exe`                  |
| Service Name     | `EndpointInventorySvc`    |
| Splunk Index     | `endpoint`                |

---

## 🧭 MITRE ATT&CK Mapping

| Tactic               | Technique                 | Reason                                    |
| -------------------- | ------------------------- | ----------------------------------------- |
| Persistence          | T1543.003 Windows Service | Services can be used to maintain access   |
| Privilege Escalation | T1543.003 Windows Service | Services may run with elevated privileges |

---

## 🔎 Splunk Search

```spl
index=endpoint host="Target-PC" ("EndpointInventorySvc" OR "sc.exe")
| table _time EventCode EventID host ComputerName source Service_Name Service_File_Name Image CommandLine Account_Name User Message _raw
| sort -_time
```

### Windows System Search

```spl
index=endpoint host="Target-PC" EventCode=7045
| table _time EventCode host ComputerName Service_Name Service_File_Name Account_Name Message _raw
| sort -_time
```

### Sysmon Process Search

```spl
index=endpoint host="Target-PC" source="*Sysmon*" EventCode=1 "sc.exe"
| table _time EventCode EventID host ComputerName Image CommandLine ParentImage User
| sort -_time
```

---

## ⚔️ Simulation

A harmless service named `EndpointInventorySvc` was created on `Target-PC` using `sc.exe`.

```cmd
sc.exe create EndpointInventorySvc binPath= "C:\Windows\System32\cmd.exe /c echo Endpoint inventory service check > C:\Windows\Temp\endpoint_inventory_service.txt" start= demand
```

Cleanup command:

```cmd
sc.exe delete EndpointInventorySvc
```

The service only wrote a simple text file and was used to generate detection telemetry.

---

## 🕵️ Analyst Review

Splunk returned new service installation evidence from `Target-PC`. Windows System Event ID `7045` confirmed that a new service was installed, and Sysmon Event ID `1` showed `sc.exe` process creation with the command line.

The service name alone does not prove malicious activity. The most important fields are the service binary path, user context, parent process, command line, and whether the service started after creation. In a real investigation, I would check whether the service runs PowerShell, `cmd.exe`, a suspicious executable, a remote path, or anything from user-writable folders like Temp, Downloads, or AppData.

---

## 🚦 Severity

| Severity | Condition                                                                             |
| -------- | ------------------------------------------------------------------------------------- |
| High     | New service installed on an endpoint                                                  |
| High     | Service runs from Temp, Downloads, or AppData                                         |
| High     | Service launches PowerShell or cmd                                                    |
| High     | Service was created by an unexpected user                                             |
| High     | Service appears after suspicious logon, download, Defender tampering, or LSASS access |

---

## ⚠️ False Positives

| Possible Cause        | Notes                                      |
| --------------------- | ------------------------------------------ |
| Software installation | Normal application or agent install        |
| Endpoint management   | Approved IT management tools               |
| Patch management      | Update or deployment activity              |
| Security tools        | EDR or monitoring deployment               |
| Admin maintenance     | Expected administrator work                |
| Lab testing           | Expected activity from this detection test |

---

## 📸 Validation Evidence

### Service Creation Command and Service Query Confirmation

<img width="624" height="154" alt="12_service_creation_command" src="https://github.com/user-attachments/assets/57301e94-860e-4fad-919f-bcd91cdf5a9f" />

### Windows System Event ID 7045 Showing New Service Installation

<img width="624" height="175" alt="12_raw_7045_new_service_installed" src="https://github.com/user-attachments/assets/ceda9448-6a5f-4af5-b707-26f636faff8a" />

### Sysmon Event ID 1 Showing sc.exe Process Creation

<img width="624" height="230" alt="12_new_service_detection" src="https://github.com/user-attachments/assets/f791aa99-a3fa-4ce2-8a6e-125ebc0dff33" />

---

## ✅ Conclusion

This detection confirmed new Windows service installation activity on `Target-PC` using Windows System Event ID `7045` and Sysmon Event ID `1`. The lab service was harmless, but the detection is useful because new services are commonly reviewed for persistence, execution, and privilege escalation. In a real SOC investigation, I would review the service name, binary path, start type, user context, parent process, command line, and surrounding endpoint activity.
