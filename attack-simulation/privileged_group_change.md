Detection 05 Privileged Group Change

The purpose of this detection was to Detect when a user is added to a privileged Active Directory group.

This detection looks for Windows Security Event ID 4728 on the domain controller.
Event ID 4728 is generated when a member is added to a security-enabled global group.

In this lab, the test user LTest / Lab Test was added to the Domain Admins group from Active Directory Users and Computers on DC01.


Lab Details
Domain: corp.local
Domain Controller: DC01
Changed User: LTest / Lab Test
Privileged Group: Domain Admins
Actor Account: Administrator
Log Source: Windows Security Logs
Forwarder: Splunk Universal Forwarder
SIEM: Splunk
Index: endpoint


MITRE Mapping
Persistence: T1098 Account Manipulation
Privilege Escalation: T1098 Account Manipulation

Adding a user to Domain Admins is a high-impact change.
If unauthorized, this can give the user broad administrative access across the domain.


Detection Logic
Look for Event ID 4728 on DC01.

This event confirms that a user was added to a security-enabled global group.
For this lab, the important fields were the actor account, the user added, the group changed, and the domain controller that logged the event.

The search was kept direct on purpose.
The goal was to validate the event first, then review the raw fields and confirm the membership change.


Splunk Search
index=endpoint host="DC01" EventCode=4728
| search "Domain Admins" "Lab Test"
| eval actor=SubjectUserName
| table _time EventCode host ComputerName actor Account_Name _raw
| sort -_time


Simulation
The group change was performed on DC01 through Active Directory Users and Computers.

Action performed:
Added Lab Test / LTest to Domain Admins

Location:
Active Directory Users and Computers
corp.local > Users > Domain Admins > Members

Expected event:
Windows Security Event ID 4728


Result
Splunk detected Event ID 4728 after the user was added to Domain Admins.

The event showed:
Event ID: 4728
Host: DC01
Actor: Administrator
User Added: Lab Test / LTest
Group Changed: Domain Admins

This confirmed that the privileged group membership change was logged and searchable in Splunk.


Analyst Checks
1.What user was added
2.What group was changed
3.Who made the change
4.Was the change expected
5.Was the user newly created
6.Was the user used to log in after the change
7.Did the same actor make any other account changes
8.Did the activity happen outside normal admin activity


Investigation Notes
I started by making the group membership change in Active Directory Users and Computers.
After the change was applied, I searched Splunk for Event ID 4728 on DC01.

The raw event confirmed that a member was added to a security-enabled global group.
The event showed the actor account as Administrator and showed Lab Test / LTest being added to Domain Admins.

This matters because Domain Admins is one of the most sensitive groups in an Active Directory environment.
An unauthorized change here could mean privilege escalation, persistence, or account compromise.

The next investigation step would be to check for follow-on activity.
That would include successful logons by the newly privileged user, additional group changes, new account creation, scheduled tasks, service creation, PowerShell activity, or other persistence behavior.


Severity
High

Adding a user to Domain Admins should be treated as high severity until confirmed as approved administrative activity.


False Positives
Approved administrator maintenance
Authorized user provisioning
Temporary privileged access
Help desk or identity management workflow
Lab-generated testing

This becomes more suspicious if the actor account is unusual, the added account was recently created, the change happens outside normal hours, or the account logs in shortly after being added.


Recommended Response
Confirm whether the group change was approved.
Identify the actor account that made the change.
Review the added user's account details.
Check if the added user logged in after the change.
Search for additional account management activity from the same actor.
Remove the user from the privileged group if the change was unauthorized.
Reset credentials if compromise is suspected.
Document the full timeline of the membership change.


Validation Evidence
1.Lab Test added to Domain Admins in Active Directory Users and Computers

<img width="624" height="360" alt="05_aduc_privileged_group_change" src="https://github.com/user-attachments/assets/5ef712d5-a304-4b7e-8453-982d89438bf1" />

2.Raw Event ID 4728 group membership change in Splunk

<img width="624" height="330" alt="05_raw_4728_group_change_event" src="https://github.com/user-attachments/assets/bb9ccbd8-deba-4e74-94e4-31866819c4c7" />

3.Splunk detection showing privileged group change

<img width="624" height="402" alt="05_privileged_group_change_detection" src="https://github.com/user-attachments/assets/1d22b09a-8ce2-4d17-b2bc-4126afe7416a" />


Analyst Conclusion
This detection validated a privileged Active Directory group membership change in the lab.

The test user LTest / Lab Test was added to the Domain Admins group on DC01.
Splunk captured the activity through Windows Security Event ID 4728.
The search confirmed the actor account, the modified group, and the user that was added.

This alert is important because unauthorized Domain Admins membership can give an attacker broad control over the domain.
In a real investigation, I would treat this as high severity until the change was confirmed as approved.

The most important next step is to check what happened after the group change.
I would look for successful logons by the newly privileged user, additional account changes, PowerShell activity, scheduled tasks, new services, or any other signs of persistence.
