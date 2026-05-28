Detection 04 New Account Created

Lab Setup
Domain: corp.local
Domain Controller: DC01
SIEM: Splunk
Log Source: Windows Security
Forwarder: Splunk Universal Forwarder
Event ID: 4720
Test Account Created: LTest

Objective
Detect when a new Active Directory domain user account is created.

This detection watches for Windows Security Event ID 4720 on the domain controller.
In the lab, the account LTest was created in Active Directory Users and Computers on DC01.

Why This Matters
A new account can be normal help desk or administrator activity.
It can also be suspicious if an attacker creates an account for persistence, future access, or privilege escalation.

In a real environment, new domain accounts should match an approved onboarding request, ticket, or administrative change.

MITRE ATT&CK
Persistence: T1136.002 Create Account: Domain Account
Privilege Escalation: T1136.002 Create Account: Domain Account

Log Source
Windows Security Event Logs
Domain Controller: DC01
Splunk index: endpoint
Event ID: 4720

Detection Logic
This detection looks for Event ID 4720 on DC01.

The important fields are:
1.created account
2.creator account
3.domain
4.host
5.event time

In this lab, the created account was LTest.
The creator account was Administrator.
The event was generated on DC01.

Splunk Search
index=endpoint host="DC01" EventCode=4720 LTest
| eval creator=mvindex(Account_Name,0)
| eval created_user=mvindex(Account_Name,1)
| table _time EventCode host ComputerName created_user creator TargetDomainName
| sort -_time

Lab Simulation
A new domain user account was created from Active Directory Users and Computers.

Created account:
LTest

Created from:
Active Directory Users and Computers

System where event was logged:
DC01

Expected event:
Windows Security Event ID 4720

Detection Result
Splunk found the new account creation event on DC01.

Result reviewed:
Created user: LTest
Creator: Administrator
Host: DC01
Event ID: 4720

What I Checked
I confirmed that Event ID 4720 was present on the domain controller.
I checked which user account was created.
I checked which account created it.
I checked the host where the event was generated.
I verified the event in Splunk instead of relying only on Active Directory Users and Computers.

Analyst Notes
A new account is not automatically malicious.
The alert matters because unauthorized account creation is a common persistence method.

The main thing I would check is whether the account creation was expected.
If there is no ticket, approval, or known admin task, this becomes more suspicious.

I would also check what happened after the account was created.
The most important follow-up searches are group membership changes and successful logons.

Follow Up Searches
Check if the account was added to a group:
index=endpoint host="DC01" (EventCode=4728 OR EventCode=4732) LTest
| table _time EventCode host Account_Name Group_Name TargetUserName
| sort -_time

Check if the new account logged in:
index=endpoint (EventCode=4624 OR EventCode=4625) (Account_Name="LTest" OR TargetUserName="LTest")
| table _time EventCode host ComputerName Account_Name TargetUserName Logon_Type Source_Network_Address
| sort -_time

Check for other account changes by the same creator:
index=endpoint host="DC01" (EventCode=4720 OR EventCode=4722 OR EventCode=4728 OR EventCode=4732)
| search Administrator
| table _time EventCode host Account_Name TargetUserName Group_Name
| sort -_time

Severity
Medium

Raise to High if:
the account was created by an unexpected user
the account was created outside normal hours
the account was added to a privileged group
the account logged in shortly after creation
the creator account has other suspicious activity

False Positives
normal user onboarding
help desk account creation
administrator testing
lab-generated account creation
temporary account creation
service account creation

Tuning Notes
This search is simple on purpose for lab validation.
In production, I would compare new account creation against HR onboarding records, ticket numbers, expected admin accounts, and known service account workflows.

Recommended Response
Confirm whether the account creation was approved.
Identify the creator account.
Review the new account group memberships.
Check if the new account logged in.
Look for privileged group changes.
Review other account management events from the same creator.
Disable the account if it was not authorized.
Document the account creation timeline.

Validation Evidence

1.New account created in Active Directory Users and Computers
<img width="563" height="468" alt="04_net_user_account_created" src="https://github.com/user-attachments/assets/da9a516d-e7f2-4ee7-a880-98070adb571e" />

2.Raw Event ID 4720 new account creation event in Splunk
<img width="624" height="137" alt="04_raw_4720_new_account_event" src="https://github.com/user-attachments/assets/d3420c64-52c2-46e3-98fb-e9ffaa55476d" />

3.Splunk detection showing created user and creator account
<img width="624" height="146" alt="04_new_account_created_detection" src="https://github.com/user-attachments/assets/ffae2dfa-7a8e-4d08-aa58-504f26e4123c" />

Analyst Conclusion
This detection confirmed that a new Active Directory domain account was created in the lab.

The account LTest was created on DC01, and Splunk captured the activity with Windows Security Event ID 4720. I used the event fields to identify both the account that was created and the account that created it.

This activity should be reviewed because a new account can be used for persistence if it was not approved. The next step would be to confirm whether the account creation was expected, then check for group membership changes and successful logons from the new account.

If the account was added to a privileged group or used to log in shortly after creation, the severity should be raised because that would suggest possible follow on activity.
