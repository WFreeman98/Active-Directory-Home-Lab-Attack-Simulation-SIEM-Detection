# active-directory-siem-detection-lab

Description: Active Directory attack simulation and Splunk SIEM detection lab

# 🛡️ Active Directory SIEM Detection Lab

### William Freeman

<div align="center">

![SIEM](https://img.shields.io/badge/SIEM-Splunk-orange)
![Domain](https://img.shields.io/badge/Domain-corp.local-blue)
![Target](https://img.shields.io/badge/Target-Windows%2010-lightgrey)
![Attack Host](https://img.shields.io/badge/Attack%20Host-Kali%20Linux-red)
![Status](https://img.shields.io/badge/Status-Validated-brightgreen)

</div>

---

> **⚠️ Legal Disclaimer**
> This lab was conducted entirely in an isolated home lab environment. No testing was performed against public systems, live networks, or unauthorized infrastructure.

---

## 📋 Table of Contents

* [Project Overview](#-project-overview)
* [Lab Environment](#-lab-environment)
* [Network Architecture](#-network-architecture)
* [Detection Rule Index](#-detection-rule-index)
* [Example Evidence](#-example-evidence)
* [Skills Demonstrated](#-skills-demonstrated)
* [What I Learned](#-what-i-learned)
* [Repository Structure](#-repository-structure)

---

## 🎯 Project Summary

I built an isolated Active Directory lab to practice SOC analyst work in a Windows domain environment. The lab includes a Windows Server 2022 domain controller, a Windows 10 workstation, a Kali Linux attack machine, and a Splunk SIEM server. I used the environment to generate controlled attack activity, collect Windows Security and Sysmon logs, and search the data in Splunk. This project includes 15 validated detections mapped to MITRE ATT&CK, covering authentication attacks, account changes, privilege changes, PowerShell activity, credential access, and persistence. The goal of this project was to show hands-on detection work by validating telemetry, writing SPL searches, reviewing false positives, and documenting what an analyst would investigate next.

---

## 🖥️ Lab Environment

| Component         | Details                                              |
| ----------------- | ---------------------------------------------------- |
| Domain            | `corp.local`                                         |
| Domain Controller | Windows Server 2022                                  |
| Workstation       | Windows 10 Target-PC                                 |
| Attack Machine    | Kali Linux                                           |
| SIEM              | Splunk on Ubuntu Server                              |
| Log Sources       | Windows Security, Sysmon, Windows System, PowerShell |
| Main Index        | `endpoint`                                           |
| Hypervisor        | VirtualBox                                           |

---

## 🌐 Network Architecture

<img width="649" height="553" alt="Lab architecture" src="https://github.com/user-attachments/assets/6a08cc82-be36-40ef-8bd2-05fc6318c967" />

---

## 🧪 Detection Rule Index

| #  | Detection                         | Log Source                | MITRE ATT&CK          | Status      | Writeup                                                        |
| -- | --------------------------------- | ------------------------- | --------------------- | ----------- | -------------------------------------------------------------- |
| 1  | RDP Brute Force                   | 4625                      | T1110 / T1021.001     | ✅ Validated | [View](attack-simulation/hydra_rdp_bruteforce.md)              |
| 2  | Successful Login After Failures   | 4625 / 4624               | T1110 / T1078         | ✅ Validated | [View](attack-simulation/successful_login_after_failures.md)   |
| 3  | Password Spraying                 | 4625                      | T1110.003             | ✅ Validated | [View](attack-simulation/password_spraying.md)                 |
| 4  | New Account Created               | 4720                      | T1136.002             | ✅ Validated | [View](attack-simulation/new_account_created.md)               |
| 5  | Privileged Group Change           | 4728 / 4732               | T1098                 | ✅ Validated | [View](attack-simulation/privileged_group_change.md)           |
| 6  | Encoded PowerShell                | Sysmon Event ID 1         | T1059.001 / T1027     | ✅ Validated | [View](attack-simulation/encoded_powershell.md)                |
| 7  | PowerShell Download Cradle        | Sysmon Event ID 1 / 3     | T1105 / T1059.001     | ✅ Validated | [View](attack-simulation/powershell_download_cradle.md)        |
| 8  | LSASS Access                      | Sysmon Event ID 10        | T1003.001             | ✅ Validated | [View](attack-simulation/lsass_access.md)                      |
| 9  | Event Log Clearing                | 1102                      | T1070.001             | ✅ Validated | [View](attack-simulation/event_log_clearing.md)                |
| 10 | Defender Tampering                | PowerShell / Sysmon       | T1562.001             | ✅ Validated | [View](attack-simulation/defender_tampering.md)                |
| 11 | Scheduled Task Created            | 4698                      | T1053.005             | ✅ Validated | [View](attack-simulation/scheduled_task_created.md)            |
| 12 | New Service Installed             | 7045                      | T1543.003             | ✅ Validated | [View](attack-simulation/new_service_installed.md)             |
| 13 | Certutil File Download            | Sysmon Event ID 1         | T1105 / T1218         | ✅ Validated | [View](attack-simulation/certutil_file_download.md)            |
| 14 | Internal Network Scan             | Sysmon Event ID 3         | T1046                 | ✅ Validated | [View](attack-simulation/internal_network_scan.md)             |
| 15 | Successful Login Then Persistence | 4624 / 4720 / 4728 / 4732 | T1078 / T1136 / T1098 | ✅ Validated | [View](attack-simulation/successful_login_then_persistence.md) |

---

## 📸 Example Evidence

### Splunk Log Ingestion

<img width="662" height="469" alt="Splunk Log Ingestion" src="https://github.com/user-attachments/assets/2500f254-2cf7-4e99-9160-f3c007708576" />

### RDP Brute Force Simulation

<img width="649" height="512" alt="Hydra Attack" src="https://github.com/user-attachments/assets/78124f35-ffdc-4a65-98d3-7c881a27278d" />

### Example Splunk Detection Result

<img width="1000" height="635" alt="Splunk Detection" src="https://github.com/user-attachments/assets/eab62698-2eba-46ba-bc8e-fdad82a70455" />

---

## 🧠 Skills Demonstrated

* Active Directory lab setup
* Windows event log analysis
* Sysmon telemetry validation
* Splunk log ingestion
* SPL detection writing
* MITRE ATT&CK mapping
* Authentication attack detection
* PowerShell activity analysis
* Persistence detection
* False positive review
* SOC-style investigation notes

---

## 🔍 Detection Validation Process

For each detection, I followed the same process:

1. Run the simulation in the lab
2. Confirm the Windows or Sysmon event exists
3. Search the raw event in Splunk
4. Identify important fields
5. Build a basic SPL search
6. Review possible false positives
7. Document analyst notes
8. Save screenshots as evidence

---

## 🧠 What I Learned

* Telemetry validation matters before writing detections.
* A tool can fail, but the logs can still show useful evidence.
* Raw events matter because fields are not always clean.
* Broad SPL searches are useful during lab validation.
* Production detections need more tuning than lab detections.
* The strongest evidence is the attack step, raw event, and Splunk result together.

---

## 📁 Repository Structure

```text
Active-Directory-SIEM-Detection-Lab/

README.md

attack-simulation/
├── hydra_rdp_bruteforce.md
├── successful_login_after_failures.md
├── password_spraying.md
├── new_account_created.md
├── privileged_group_change.md
├── encoded_powershell.md
├── powershell_download_cradle.md
├── lsass_access.md
├── event_log_clearing.md
├── defender_tampering.md
├── scheduled_task_created.md
├── new_service_installed.md
├── certutil_file_download.md
├── internal_network_scan.md
└── successful_login_then_persistence.md

validation/
└── detection_validation_matrix.md
```
