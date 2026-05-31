# successful login then persistence detection

Description: Detecting a successful remote logon followed by account creation and local administrator group modification

# 🔐 Successful Login Then Persistence Detection

<div align="center">

![Log Source](https://img.shields.io/badge/Log%20Source-Windows%20Security-blue)
![Event IDs](https://img.shields.io/badge/Event%20IDs-4624%20%7C%204720%20%7C%204732-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![MITRE](https://img.shields.io/badge/MITRE-T1078%20%7C%20T1136.001%20%7C%20T1098-red)
![Status](https://img.shields.io/badge/Status-Validated-brightgreen)

</div>

---

## 📋 Table of Contents

* [Detection Summary](#-detection-summary)
* [Lab Details](#-lab-details)
* [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
* [Splunk Searches](#-splunk-searches)
* [Simulation](#-simulation)
* [Analyst Review](#-analyst-review)
* [Severity](#-severity)
* [False Positives](#-false-positives)
* [Cleanup](#-cleanup)
* [Validation Evidence](#-validation-evidence)
* [Conclusion](#-conclusion)

---

## 🎯 Detection Summary

This detection identifies a successful remote logon followed by persistence activity. I tested it by logging into `Target-PC` over RDP from Kali, creating a local account named `svc_backup`, and adding that account to the local `Administrators` group. The goal was to validate a multi-event sequence using Windows Security Event IDs `4624`, `4720`, and `4732`.

---

## 🧪 Lab Details

| Field               | Details               |
| ------------------- | --------------------- |
| Target Host         | `Target-PC`           |
| Source IP           | `192.168.10.250`      |
| Logon Account       | `Administrator`       |
| Persistence Account | `svc_backup`          |
| Group Modified      | `Administrators`      |
| Log Source          | Windows Security Logs |
| SIEM                | Splunk                |
| Index               | `endpoint`            |

---

## 🧭 MITRE ATT&CK Mapping

| Tactic                             | Technique                               | Reason                                                   |
| ---------------------------------- | --------------------------------------- | -------------------------------------------------------- |
| Initial Access / Defense Evasion   | T1078 Valid Accounts                    | A valid account successfully logged in over RDP          |
| Persistence                        | T1136.001 Create Account: Local Account | A local account named `svc_backup` was created           |
| Persistence / Privilege Escalation | T1098 Account Manipulation              | `svc_backup` was added to the local Administrators group |

---

## 🔎 Splunk Searches

### Successful RDP Logon

```spl
index=endpoint host="Target-PC" EventCode=4624 "192.168.10.250"
| table _time EventCode host ComputerName Account_Name Logon_Type Source_Network_Address _raw
| sort -_time
```

### Local Account Creation

```spl
index=endpoint host="Target-PC" EventCode=4720 "svc_backup"
| table _time EventCode host ComputerName _raw
| sort -_time
```

### Local Administrator Group Change

```spl
index=endpoint host="Target-PC" EventCode=4732 "svc_backup"
| table _time EventCode host ComputerName _raw
| sort -_time
```

---

## ⚔️ Simulation

A successful RDP login was performed from Kali to `Target-PC` using a valid administrative account.

```text
Source IP: 192.168.10.250
```

A local account was created on `Target-PC`.

```cmd
net user svc_backup * /add
```

The account was added to the local `Administrators` group.

```cmd
net localgroup Administrators svc_backup /add
```

The account was verified using:

```cmd
net user svc_backup
```

The password was entered through the hidden prompt and was not recorded in screenshots.

---

## 🕵️ Analyst Review

A successful logon followed by account creation and administrator group modification can indicate post-compromise persistence. Each event may be legitimate by itself, but the sequence becomes more suspicious when it occurs shortly after a remote logon or from an unusual source.

In this lab, Event ID `4624` showed a successful RDP logon from `192.168.10.250`, Event ID `4720` showed the `svc_backup` account creation, and Event ID `4732` showed the account being added to the local `Administrators` group. In a real investigation, I would review the source IP, logged-in account, new account, group membership change, timing, and surrounding endpoint activity.

---

## 🚦 Severity

| Severity | Condition                                                                                        |
| -------- | ------------------------------------------------------------------------------------------------ |
| High     | Successful remote logon followed by account creation                                             |
| High     | New account added to local Administrators                                                        |
| High     | Source IP or logon account is unusual                                                            |
| High     | Activity is not tied to an approved change                                                       |
| High     | Follow-on activity appears, such as PowerShell, services, scheduled tasks, or Defender tampering |

---

## ⚠️ False Positives

| Possible Cause           | Notes                                      |
| ------------------------ | ------------------------------------------ |
| Admin provisioning       | Approved account creation                  |
| Help desk recovery       | Authorized account recovery work           |
| IT maintenance           | Expected administrative activity           |
| Service account creation | Approved service account setup             |
| Lab testing              | Expected activity from this detection test |

---

## 🧹 Cleanup

After validation, the test account was removed.

```cmd
net localgroup Administrators svc_backup /delete
net user svc_backup /delete
```

---

## 📸 Validation Evidence

### Windows Security Event ID 4624 Showing Successful RDP Logon From Kali

<img width="624" height="379" alt="4624 Logon Type 10 from Kali IP" src="https://github.com/user-attachments/assets/79640665-3aad-4bb7-a97a-9415e74acf3d" />

### Windows Security Event ID 4720 Showing svc_backup Account Creation

<img width="624" height="394" alt="svc_backup account exists and is in Administrators" src="https://github.com/user-attachments/assets/df1ae9e1-6b85-43e6-9003-e6c37daa7500" />

### Windows Security Event ID 4732 Showing svc_backup Added to Administrators

<img width="624" height="325" alt="4732 showing svc_backup added to Administrators" src="https://github.com/user-attachments/assets/dc1885b7-28f7-4bcd-800c-5f15faa08da1" />

---

## ✅ Conclusion

This detection validated a successful login followed by persistence activity on `Target-PC`. Windows Security Event IDs `4624`, `4720`, and `4732` showed the timeline from remote logon to local account creation and administrator group membership modification. In a real SOC investigation, I would treat this as high priority until the logon, account creation, and group change were confirmed as approved.
