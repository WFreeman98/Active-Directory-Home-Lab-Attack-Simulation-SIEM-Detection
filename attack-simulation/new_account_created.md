# new account created detection

Description: Detecting new Active Directory domain account creation using Windows Security Event ID 4720

# 👤 New Account Created Detection

<div align="center">

![Log Source](https://img.shields.io/badge/Log%20Source-Windows%20Security-blue)
![Event ID](https://img.shields.io/badge/Event%20ID-4720-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![MITRE](https://img.shields.io/badge/MITRE-T1136.002-red)
![Status](https://img.shields.io/badge/Status-Validated-brightgreen)

</div>

---

## 📋 Table of Contents

* [Detection Summary](#-detection-summary)
* [Lab Details](#-lab-details)
* [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
* [Splunk Search](#-splunk-search)
* [Analyst Review](#-analyst-review)
* [Follow-Up Searches](#-follow-up-searches)
* [Severity](#-severity)
* [False Positives](#-false-positives)
* [Validation Evidence](#-validation-evidence)
* [Conclusion](#-conclusion)

---

## 🎯 Detection Summary

This detection identifies when a new Active Directory domain user account is created. I tested it by creating the account `LTest` in Active Directory Users and Computers on `DC01` and validating the event in Splunk. The goal was to confirm that Windows Security Event ID `4720` captured the account creation and that the event could be reviewed for the created user, creator account, host, and domain.

---

## 🧪 Lab Details

| Field                | Details                    |
| -------------------- | -------------------------- |
| Domain               | `corp.local`               |
| Domain Controller    | `DC01`                     |
| SIEM                 | Splunk                     |
| Log Source           | Windows Security           |
| Forwarder            | Splunk Universal Forwarder |
| Event ID             | `4720`                     |
| Test Account Created | `LTest`                    |
| Splunk Index         | `endpoint`                 |

---

## 🧭 MITRE ATT&CK Mapping

| Tactic               | Technique                                | Reason                                                    |
| -------------------- | ---------------------------------------- | --------------------------------------------------------- |
| Persistence          | T1136.002 Create Account: Domain Account | A new domain account can be created for future access     |
| Privilege Escalation | T1136.002 Create Account: Domain Account | A created account may later be added to privileged groups |

---

## 🔎 Splunk Search

```spl
index=endpoint host="DC01" EventCode=4720 LTest
| eval creator=mvindex(Account_Name,0)
| eval created_user=mvindex(Account_Name,1)
| table _time EventCode host ComputerName created_user creator TargetDomainName
| sort -_time
```

---

## 🕵️ Analyst Review

A new account is not automatically malicious, but it should match an approved onboarding request, ticket, or administrative change. In this lab, the created account was `LTest`, the creator account was `Administrator`, and the event was generated on `DC01`.

The main follow-up is to check what happened after the account was created. If the account was added to a privileged group or logged in shortly after creation, the severity should increase.

---

## 🔁 Follow-Up Searches

### Check if the account was added to a group

```spl
index=endpoint host="DC01" (EventCode=4728 OR EventCode=4732) LTest
| table _time EventCode host Account_Name Group_Name TargetUserName
| sort -_time
```

### Check if the new account logged in

```spl
index=endpoint (EventCode=4624 OR EventCode=4625) (Account_Name="LTest" OR TargetUserName="LTest")
| table _time EventCode host ComputerName Account_Name TargetUserName Logon_Type Source_Network_Address
| sort -_time
```

### Check other account changes by the same creator

```spl
index=endpoint host="DC01" (EventCode=4720 OR EventCode=4722 OR EventCode=4728 OR EventCode=4732)
| search Administrator
| table _time EventCode host Account_Name TargetUserName Group_Name
| sort -_time
```

---

## 🚦 Severity

| Severity | Condition                                       |
| -------- | ----------------------------------------------- |
| Medium   | New domain account created                      |
| High     | Account was created by an unexpected user       |
| High     | Account was added to a privileged group         |
| High     | Account logged in shortly after creation        |
| High     | Creator account shows other suspicious activity |

---

## ⚠️ False Positives

| Possible Cause           | Notes                                      |
| ------------------------ | ------------------------------------------ |
| User onboarding          | Normal account creation for a new employee |
| Help desk activity       | Approved account creation                  |
| Admin testing            | Administrator created a test account       |
| Service account creation | New service account for business use       |
| Lab testing              | Expected activity from this detection test |

---

## 📸 Validation Evidence

### New Account Created in Active Directory Users and Computers

<img width="563" height="468" alt="04_net_user_account_created" src="https://github.com/user-attachments/assets/da9a516d-e7f2-4ee7-a880-98070adb571e" />

### Raw Event ID 4720 New Account Creation Event in Splunk

<img width="624" height="137" alt="04_raw_4720_new_account_event" src="https://github.com/user-attachments/assets/d3420c64-52c2-46e3-98fb-e9ffaa55476d" />

### Splunk Detection Showing Created User and Creator Account

<img width="624" height="146" alt="04_new_account_created_detection" src="https://github.com/user-attachments/assets/ffae2dfa-7a8e-4d08-aa58-504f26e4123c" />

---

## ✅ Conclusion

This detection confirmed that a new Active Directory domain account was created in the lab. Splunk captured the `LTest` account creation on `DC01` using Windows Security Event ID `4720`. The next step would be to confirm whether the account creation was approved, then check for group membership changes and successful logons from the new account.
