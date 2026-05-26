Detection 3 Password Spraying

Purpose
Detect password spraying activity against multiple Windows domain user accounts.

This detection looks for one source IP generating failed logons against more than one user account.
The lab activity was generated from Kali against Target-PC.
The main event used for this detection is Windows Security Event ID 4625.

Lab Systems
Attacker: Kali Linux
Target: Target-PC
Domain: corp.local
SIEM: Splunk
Log Source: Windows Security
Forwarder: Splunk Universal Forwarder

MITRE ATT&CK
Credential Access: T1110.003 Password Spraying
Lateral Movement: T1021.001 Remote Services: Remote Desktop Protocol

Why This Matters
Password spraying is different from normal brute forcing.
A brute force attack usually tries many passwords against one account.
Password spraying usually tries one password against many accounts.

That makes spraying harder to catch if the attacker moves slowly.
The important pattern is not just the number of failures.
The important pattern is one source touching multiple accounts.

Expected Logs
Event ID: 4625
Host: Target-PC
Source IP: 192.168.10.250
Logon Type: 3
Result: failed authentication
Pattern: multiple users targeted from the same source IP

Users Tested
PWaltz@corp.local
AJones@corp.local
TLee@corp.local
BWaltz@corp.local
JGarcia@corp.local
MJones@corp.local

Kali Command
hydra -L spray_users.txt -p 'Kali2026' rdp://192.168.10.100 -V -t 1

Notes
The password was intentionally wrong.
The goal was to generate failed authentication logs, not gain access.
This was done in an isolated lab environment.

Splunk Search
index=endpoint host="Target-PC" EventCode=4625
| eval source_ip=coalesce(Source_Network_Address, IpAddress, Workstation_Name)
| eval user=lower(coalesce(TargetUserName, Account_Name))
| where source_ip="192.168.10.250"
| stats count as failure_count dc(user) as unique_users values(user) as targeted_users values(Logon_Type) as logon_types by source_ip host ComputerName
| where unique_users >= 3 AND failure_count >= 3
| sort -unique_users

What The Search Does
Searches for failed Windows logons.
Normalizes the source IP field.
Normalizes the username field.
Limits the activity to the Kali attacker IP.
Counts how many failures happened.
Counts how many unique users were targeted.
Shows the targeted users in the result.
Flags the activity when at least 3 users were targeted.

Fields I Checked
1.time
2.host
3.ComputerName
4.EventCode
5.TargetUserName
6.Account Name
7.Source Network Address
8.IpAddress
9.Workstation Name
10.Logon Type
11.Failure Reason

Detection Result
The search showed failed logons from 192.168.10.250.
The failures targeted multiple domain users.
The destination system was Target-PC.
The failed logons appeared as Logon Type 3.
That behavior matched the expected RDP/NLA password spray activity.

Analyst Notes
I treated this differently than the RDP brute force detection.
The brute force detection focused on repeated failures against one user.
This detection focused on one source IP targeting multiple users.

The unique user count is the main signal here.
A single failed login is not enough.
A few failures against different users from the same source is more suspicious.

The next check would be Event ID 4624.
If any sprayed account logs in successfully after the failures, the alert should be treated as possible account compromise.

Follow Up Search
index=endpoint host="Target-PC" (EventCode=4625 OR EventCode=4624)
| eval source_ip=coalesce(Source_Network_Address, IpAddress, Workstation_Name)
| eval user=lower(coalesce(TargetUserName, Account_Name))
| where source_ip="192.168.10.250"
| table _time EventCode source_ip user host ComputerName Logon_Type Failure_Reason
| sort _time

What I Would Check Next
Check if any targeted user had a successful Event ID 4624.
Check if the same source IP targeted other hosts.
Check if the source IP is expected in the environment.
Check if any accounts were locked out.
Check if the activity happened outside normal hours.
Check for PowerShell, new services, scheduled tasks, or account changes after any successful login.

Severity
Medium

Raise To High If
A targeted user has a successful Event ID 4624 after the spray.
The source IP is unknown or external.
The same source targets multiple systems.
The activity happens outside normal business hours.
There is follow-on activity after authentication.

False Positives
Help desk testing.
Administrator testing.
User onboarding.
Misconfigured authentication scripts.
Password policy testing.
Lab-generated authentication testing.

Tuning Notes
The lab query is intentionally simple.
For production, I would add a time window.
I would also exclude known admin systems and approved testing hosts.
I would tune the unique user threshold based on normal login behavior.
I would alert higher when a successful login follows the spray.

Response Notes
Identify the source IP.
Review the targeted accounts.
Confirm whether the activity was authorized.
Search for successful logons after the spray.
Check for account lockouts.
Reset passwords if compromise is suspected.
Restrict RDP exposure where possible.
Enforce MFA where possible.
Document the full authentication timeline.

Validation Evidence

1.Hydra password spray from Kali

<img width="624" height="282" alt="03_hydra_password_spray" src="https://github.com/user-attachments/assets/28bbfe5e-93c8-4509-833b-9c27e2045602" />

2.Raw Event ID 4625 failed logons against multiple users
<img width="624" height="308" alt="03_raw_4625_multiple_users" src="https://github.com/user-attachments/assets/07cdf712-0470-4a37-b2ce-0b11b01511b3" />

3.Splunk detection showing multiple targeted users from one source IP
<img width="624" height="255" alt="03_password_spraying_detection" src="https://github.com/user-attachments/assets/45af8170-bd86-41c6-be2e-1f5ba94a260a" />

Conclusion
This detection validated password spraying behavior in the lab.
Hydra attempted one password across multiple domain accounts.
Target-PC generated Windows Security Event ID 4625 failed logons from the Kali source IP.
The Splunk search grouped the failures by source IP and counted unique targeted users.

The activity should be treated as suspected password spraying.
The most important next step is to check for successful Event ID 4624 logons after the failed attempts.
