# internal network scan detection

Description: Detecting internal network scanning activity using Windows Filtering Platform events

# 🔎 Internal Network Scan Detection

<div align="center">

![Log Source](https://img.shields.io/badge/Log%20Source-Windows%20Security-blue)
![Event ID](https://img.shields.io/badge/Event%20ID-5156-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![MITRE](https://img.shields.io/badge/MITRE-T1046-red)
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

This detection identifies internal network scanning activity from one host to another. I tested it by running an Nmap scan from Kali against `Target-PC` and validating the traffic in Splunk using Windows Security Event ID `5156`. The goal was to confirm that Windows Filtering Platform events showed inbound connection activity from the scanner to the target.

---

## 🧪 Lab Details

| Field          | Details                    |
| -------------- | -------------------------- |
| Scanner        | Kali Linux                 |
| Target         | `Target-PC`                |
| Source IP      | `192.168.10.250`           |
| Destination IP | `192.168.10.100`           |
| Log Source     | Windows Security           |
| Telemetry      | Windows Filtering Platform |
| Event ID       | `5156`                     |
| SIEM           | Splunk                     |
| Index          | `endpoint`                 |

---

## 🧭 MITRE ATT&CK Mapping

| Tactic    | Technique                      | Reason                                             |
| --------- | ------------------------------ | -------------------------------------------------- |
| Discovery | T1046 Network Service Scanning | Nmap was used to scan TCP ports on the target host |

---

## 🔎 Splunk Search

```spl
index=endpoint host="Target-PC" EventCode=5156 "192.168.10.250"
| table _time EventCode host ComputerName Direction SourceAddress SourcePort DestAddress DestPort Protocol Application
| sort -_time
```

### Port Count Search

```spl
index=endpoint host="Target-PC" EventCode=5156 "192.168.10.250"
| stats count dc(DestPort) as unique_ports values(DestPort) as scanned_ports by SourceAddress DestAddress host
| sort -unique_ports
```

---

## ⚔️ Simulation

A controlled Nmap scan was launched from Kali against `Target-PC`.

```bash
nmap -sS -Pn -p 1-1000 192.168.10.100
```

The scan targeted TCP ports `1-1000` on `Target-PC`. Nmap identified TCP port `135` as open. This test did not exploit the target, brute-force credentials, or modify the system.

---

## 🕵️ Analyst Review

Splunk returned Windows Filtering Platform Event ID `5156` events from `Target-PC`. The events showed inbound traffic from `192.168.10.250`, which matched the Kali scanner, to `192.168.10.100`, which matched `Target-PC`.

One connection to one port is not enough by itself to prove scanning. The stronger signal is one source contacting multiple ports or multiple hosts. In a real investigation, I would confirm whether the source is an approved scanner, review the scanned ports, and check for follow-on activity such as failed logons, successful logons, service creation, scheduled tasks, PowerShell activity, or lateral movement.

---

## 🚦 Severity

| Severity | Condition                                                                                     |
| -------- | --------------------------------------------------------------------------------------------- |
| Medium   | One internal source scans ports on another internal host                                      |
| High     | Source host is not approved for scanning                                                      |
| High     | Scan targets many hosts or sensitive systems                                                  |
| High     | Scan is followed by failed or successful logons                                               |
| High     | Scan is followed by service creation, scheduled tasks, PowerShell activity, or file downloads |

---

## ⚠️ False Positives

| Possible Cause         | Notes                                      |
| ---------------------- | ------------------------------------------ |
| Vulnerability scanning | Approved scanner activity                  |
| Admin troubleshooting  | IT testing ports or connectivity           |
| Asset inventory        | Internal discovery tools                   |
| Endpoint management    | Management platform activity               |
| Security testing       | Authorized testing                         |
| Lab testing            | Expected activity from this detection test |

---

## 📸 Validation Evidence

### Kali Nmap Scan Against Target-PC

<img width="624" height="237" alt="14_nmap_scan_command" src="https://github.com/user-attachments/assets/355ae7c9-d72c-4b34-9bcf-a1e0937fbd33" />

### Raw Windows Filtering Platform Event ID 5156 Showing Inbound Connection From Kali

<img width="624" height="348" alt="14_raw_firewall_scan_events" src="https://github.com/user-attachments/assets/f4791a75-10ac-4d83-b559-ee81f34eeb9e" />

### Splunk Detection Query Showing Firewall Events Involving Kali IP

<img width="624" height="163" alt="14_internal_network_scan_detection" src="https://github.com/user-attachments/assets/983efc69-a899-46e1-9550-1312769508f1" />

---

## ✅ Conclusion

This detection confirmed internal network scanning activity from Kali to `Target-PC` using Windows Filtering Platform Event ID `5156`. The Nmap scan targeted TCP ports `1-1000`, and Splunk showed inbound connection events from `192.168.10.250` to `192.168.10.100`. In a real SOC investigation, I would first confirm whether the source host is an approved scanner, then review scanned ports, affected hosts, and any follow-on activity after the scan.
