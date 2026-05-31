# powershell download cradle detection

Description: Detecting PowerShell network activity used to download content from a remote web server

# 🌐 PowerShell Download Cradle Detection

<div align="center">

![Log Source](https://img.shields.io/badge/Log%20Source-Sysmon-blue)
![Event ID](https://img.shields.io/badge/Event%20ID-3-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![MITRE](https://img.shields.io/badge/MITRE-T1059.001%20%7C%20T1105-red)
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

This detection identifies PowerShell being used to download content from a remote web server. I tested it by hosting a harmless text file on Kali and downloading it from `Target-PC` using PowerShell. The goal was to confirm that Sysmon Event ID `3` captured the network connection and that Splunk could identify PowerShell connecting to the Kali web server.

---

## 🧪 Lab Details

| Field            | Details          |
| ---------------- | ---------------- |
| Host             | `Target-PC`      |
| Attacker         | Kali Linux       |
| Destination IP   | `192.168.10.250` |
| Destination Port | `8000`           |
| Log Source       | Sysmon           |
| Event ID         | `3`              |
| SIEM             | Splunk           |
| Index            | `endpoint`       |

---

## 🧭 MITRE ATT&CK Mapping

| Tactic              | Technique                   | Reason                                               |
| ------------------- | --------------------------- | ---------------------------------------------------- |
| Execution           | T1059.001 PowerShell        | PowerShell was used to retrieve remote content       |
| Command and Control | T1105 Ingress Tool Transfer | The host downloaded content from a remote web server |

---

## 🔎 Splunk Search

```spl
index=endpoint host="Target-PC" source="*Sysmon*" EventCode=3
| search DestinationIp="192.168.10.250" DestinationPort=8000
| table _time host ComputerName Image User DestinationIp DestinationPort DestinationHostname Protocol
| sort -_time
```

---

## ⚔️ Simulation

A harmless text file was created and hosted on Kali using Python's built-in web server.

```bash
mkdir -p /home/kali/soc-web
cd /home/kali/soc-web
echo "SOC Lab PowerShell Download Cradle Test" > test.txt
python3 -m http.server 8000
```

The file was downloaded from `Target-PC` using PowerShell.

```powershell
Invoke-WebRequest -Uri "http://192.168.10.250:8000/test.txt" -OutFile "$env:TEMP\soc_lab_test.txt"
```

File verification:

```powershell
Get-Content "$env:TEMP\soc_lab_test.txt"
```

Expected output:

```text
SOC Lab PowerShell Download Cradle Test
```

---

## 🕵️ Analyst Review

PowerShell downloads are not always malicious, but they should be reviewed because attackers often use PowerShell to retrieve scripts, tools, or payloads. In this lab, Sysmon Event ID `3` confirmed that `Target-PC` connected to `192.168.10.250` on port `8000`.

The main investigation question is not only whether PowerShell made a network connection. The important question is what was downloaded, where it was saved, and whether anything executed afterward.

---

## 🚦 Severity

| Severity | Condition                                                                     |
| -------- | ----------------------------------------------------------------------------- |
| Medium   | PowerShell connects to a remote web server                                    |
| High     | Downloaded file is executable                                                 |
| High     | File runs after download                                                      |
| High     | Destination is external or suspicious                                         |
| High     | Activity is followed by persistence, credential access, or Defender tampering |

---

## ⚠️ False Positives

| Possible Cause      | Notes                                      |
| ------------------- | ------------------------------------------ |
| Admin scripts       | Approved PowerShell downloads              |
| Software deployment | Endpoint management tools                  |
| Internal automation | Normal scripted activity                   |
| Security testing    | Authorized testing                         |
| Lab testing         | Expected activity from this detection test |

---

## 📸 Validation Evidence

### Kali Web Server Hosting the Test File

<img width="624" height="280" alt="07_kali_web_server_hosting_file" src="https://github.com/user-attachments/assets/9ce24c53-9579-42a1-989d-75c9d3c767d2" />

### Raw Sysmon Event ID 3 Network Connection Evidence

<img width="624" height="276" alt="07_raw_sysmon_powershell_download_events" src="https://github.com/user-attachments/assets/6340c5d5-b11a-4bd7-a4c5-3c030e805ecb" />

### Splunk Detection Showing Target-PC Connection to Kali Web Server

<img width="624" height="277" alt="07_powershell_download_cradle_detection" src="https://github.com/user-attachments/assets/82ce02a7-3e6f-4f54-8100-787fc1708767" />

---

## ✅ Conclusion

This detection confirmed PowerShell download cradle behavior from `Target-PC` to the Kali web server. The file used in the lab was harmless, but the behavior is important because PowerShell is commonly used to retrieve remote content during attacker activity. In a real investigation, I would review the downloaded file, check for file creation, look for child process execution, and search for follow-on activity such as persistence, credential access, or defense evasion.

The activity was safely simulated with a harmless text file, but the behavior is still important because attackers commonly use PowerShell to retrieve scripts, tools, or payloads from remote infrastructure. Splunk showed Sysmon Event ID 3 network telemetry, which confirmed that Target-PC connected to 192.168.10.250 on port 8000.

The main investigation point is not just that PowerShell made a network connection. The important question is what was downloaded and what happened next. In a real SOC investigation, I would review the downloaded file, check for file creation, look for child process execution, and search for any follow-on activity such as persistence, credential access, or defense evasion.
