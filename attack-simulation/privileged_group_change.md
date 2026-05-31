# privileged group change detection

Description: Detecting when a user is added to a privileged Active Directory group

# 🔐 Privileged Group Change Detection

<div align="center">

![Log Source](https://img.shields.io/badge/Log%20Source-Windows%20Security-blue)
![Event ID](https://img.shields.io/badge/Event%20ID-4728-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![MITRE](https://img.shields.io/badge/MITRE-T1098-red)
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

This detection identifies when a user is added to a privileged Active Directory group. I tested it by adding `LTest / Lab Test` to the `Domain Admins` group on `DC01` and validating the activity in Splunk. The goal was to confirm that Windows Security Event ID `4728` captured the group membership change and showed the actor account, added user, and modified group.

---

## 🧪 Lab Details

| Field             | Details                    |
| ----------------- | -------------------------- |
| Domain            | `corp.local`               |
| Domain Controller | `DC01`                     |
| Changed User      | `LTest / Lab Test`         |
| Privileged Group  | `Domain Admins`            |
| Actor Account     | `Administrator`            |
| Log Source        | Windows Security Logs      |
| Forwarder         | Splunk Universal Forwarder |
| SIEM              | Splunk                     |
| Index             | `endpoint`                 |
| Event ID          | `4728`                     |

---

## 🧭 MITRE ATT&CK Mapping

| Tactic               | Technique                  | Reason                                                          |
| -------------------- | -------------------------- | --------------------------------------------------------------- |
| Persistence          | T1098 Account Manipulation | A user was added to a privileged group                          |
| Privilege Escalation | T1098 Account Manipulation | Domain Admins membership can give broad control over the domain |

---

## 🔎 Splunk Search

```spl
index=endpoint host="DC01" EventCode=4728
| search "Domain Admins" "Lab Test"
| eval actor=SubjectUserName
| table _time EventCode host ComputerName actor Account_Name _raw
| sort -_time
```

---

## ⚔️ Simulation

The group change was performed on `DC01` through Active Directory Users and Computers.

| Field          | Details                                        |
| -------------- | ---------------------------------------------- |
| Action         | Added `Lab Test / LTest` to `Domain Admins`    |
| Location       | Active Directory Users and Computers           |
| Path           | `corp.local > Users > Domain Admins > Members` |
| Expected Event | Windows Security Event ID `4728`               |

---

## 🕵️ Analyst Review

Adding a user to `Domain Admins` is a high-impact change because it can give the account broad administrative access across the domain. In this lab, Splunk detected Event ID `4728` after `Lab Test / LTest` was added to `Domain Admins` by `Administrator`.

The main follow-up is to confirm whether the change was approved. If the user was recently created, logged in shortly after the change, or the actor account shows other suspicious activity, the alert should be treated as more serious.

---

## 🚦 Severity

| Severity | Condition                                                 |
| -------- | --------------------------------------------------------- |
| High     | User added to `Domain Admins`                             |
| High     | Change was made by an unexpected actor                    |
| High     | Added account was recently created                        |
| High     | Added account logged in shortly after the change          |
| High     | Additional account changes or persistence activity appear |

---

## ⚠️ False Positives

| Possible Cause      | Notes                                      |
| ------------------- | ------------------------------------------ |
| Approved admin work | Normal administrator maintenance           |
| User provisioning   | Authorized privileged access setup         |
| Temporary access    | Short-term privileged access assignment    |
| Help desk workflow  | Approved identity management process       |
| Lab testing         | Expected activity from this detection test |

---

## 📸 Validation Evidence

### Lab Test Added to Domain Admins in Active Directory Users and Computers

<img width="624" height="360" alt="05_aduc_privileged_group_change" src="https://github.com/user-attachments/assets/5ef712d5-a304-4b7e-8453-982d89438bf1" />

### Raw Event ID 4728 Group Membership Change in Splunk

<img width="624" height="330" alt="05_raw_4728_group_change_event" src="https://github.com/user-attachments/assets/bb9ccbd8-deba-4e74-94e4-31866819c4c7" />

### Splunk Detection Showing Privileged Group Change

<img width="624" height="402" alt="05_privileged_group_change_detection" src="https://github.com/user-attachments/assets/1d22b09a-8ce2-4d17-b2bc-4126afe7416a" />

---

## ✅ Conclusion

This detection validated a privileged Active Directory group membership change in the lab. `LTest / Lab Test` was added to `Domain Admins` on `DC01`, and Splunk captured the activity through Windows Security Event ID `4728`. In a real investigation, I would treat this as high severity until the change was confirmed as approved, then check for successful logons, additional account changes, PowerShell activity, scheduled tasks, new services, or other signs of persistence.

