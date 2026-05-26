Detection 2 Successful Login After Failures

Purpose

Detect repeated failed RDP logons that are followed by a successful logon from the same source IP and same user.

This is more serious than failed logons by themselves.
Failed logons can be noise.
Failed logons followed by success can mean the password was guessed or valid credentials were used.

Lab Details

Target host: Target-PC
Domain: CORP
User tested: bwaltz
Source IP: 192.168.10.250
Attacker system: Kali Linux
Log source: Windows Security logs
SIEM: Splunk
Index: endpoint

Events codes looked for

4625 Failed logon
4624 Successful logon

Logon Types Watched

Logon Type 3
Network logon
Seen during RDP/NLA failed authentication in this lab.

Logon Type 10
RemoteInteractive logon
Seen during the successful RDP session in this lab.

MITRE Mapping

T1110 Brute Force
Repeated failed logons were generated against the same domain user.

T1078 Valid Accounts
A successful logon happened after the failed attempts.

T1021.001 Remote Services RDP
The authentication activity was tied to RDP access against the workstation.

Attack Simulation

Failed RDP attempts from Kali

hydra -l bwaltz -P passwords_wrong.txt rdp://192.168.10.100 -V -t 1

After the failed attempts, I made a successful RDP login from the same Kali machine.

Successful RDP login

xfreerdp /v:192.168.10.100 /d:CORP /u:bwaltz /cert:ignore

The working password was not placed in the documentation.

Splunk Search

index=endpoint host="Target-PC" (EventCode=4625 OR EventCode=4624) (TargetUserName="bwaltz" OR Account_Name="bwaltz")
| where Source_Network_Address="192.168.10.250"
| eval user=coalesce(TargetUserName, Account_Name)
| eval failure_time=if(EventCode=4625,_time,null())
| eval success_time=if(EventCode=4624,_time,null())
| stats count(eval(EventCode=4625)) as failure_count count(eval(EventCode=4624)) as success_count earliest(failure_time) as first_failure latest(failure_time) as last_failure earliest(success_time) as first_success values(Logon_Type) as logon_types by Source_Network_Address user host ComputerName
| where failure_count >= 5 AND success_count >= 1 AND first_success > first_failure
| convert ctime(first_failure) ctime(last_failure) ctime(first_success)
| sort -failure_count

What The Search Does

Looks for 4625 and 4624 events on Target-PC.
Filters to the test user bwaltz.
Filters to the Kali source IP.
Counts failed logons and successful logons.
Keeps only activity where failures happened before success.
Shows the first failure time, last failure time, and first successful login time.

Why This Matters

A normal brute force alert only proves that authentication failed.
This detection checks whether the activity turned into a successful login.

That changes the investigation.
At that point I would stop treating it like only attempted access and start checking for possible account compromise.

Fields I Checked

1.EventCode

2.TargetUserName

3.Account Name

4.Source Network Address

5.Logon Type

6.ComputerName

7.host

8.time

Result

The search showed repeated failed logons for bwaltz from 192.168.10.250.
The same source IP later generated successful logon activity for the same user.

The failed attempts appeared as Logon Type 3.
The successful RDP session appeared as Logon Type 10.

This matched the behavior I expected from the lab.

Analyst Checks

Confirm the source IP.
Confirm the targeted user.
Confirm the successful logon happened after the failures.
Check whether the source IP is normal for that user.
Check whether the login happened outside normal hours.
Check whether the same source IP hit other users.
Check whether the same user had failures from other IPs.
Check for post-login activity.

Follow Up Searches

Successful logons from same source

index=endpoint host="Target-PC" EventCode=4624
| search Source_Network_Address="192.168.10.250"
| table _time host ComputerName Account_Name TargetUserName Source_Network_Address Logon_Type
| sort -_time

Other users targeted by same source

index=endpoint EventCode=4625 Source_Network_Address="192.168.10.250"
| stats count by Account_Name TargetUserName host ComputerName Logon_Type
| sort -count

Post login PowerShell activity

index=endpoint host="Target-PC" source="*Sysmon*" ("powershell.exe" OR "pwsh.exe")
| table _time host Image CommandLine ParentImage User EventCode EventID
| sort -_time

Account or group changes after login

index=endpoint (EventCode=4720 OR EventCode=4728 OR EventCode=4732)
| table _time host ComputerName Subject_Account_Name Target_Account_Name Group_Name EventCode
| sort -_time

Severity

High

Reason:
The same source IP had repeated failed authentication attempts and later authenticated successfully as the same user.

Keep as Medium if it is confirmed to be normal user behavior.
Treat as High if the source IP is unusual, the login is unexpected, or post-login activity appears suspicious.

False Positives

User typed the wrong password several times and then got it right.
Help desk or admin testing.
Saved RDP credentials were outdated and then corrected.
Lab testing.
A user recently changed their password.
Automated process tried old credentials before a real login.

Tuning Notes

This detection is intentionally strict on source IP and user so the alert is easier to validate in the lab.

In production I would tune it by:
requiring a higher failure count
using a short time window
excluding known admin jump boxes
excluding approved vulnerability scanners
adding known business hours context
checking whether the source IP is normal for the user
correlating with endpoint process activity after success

Response Notes

Confirm whether bwaltz was expected to log in from 192.168.10.250.
Review the timeline of failed and successful logons.
Check for PowerShell, new services, scheduled tasks, new accounts, or group changes after the success.
Reset the account password if compromise is suspected.
Restrict RDP access if it is exposed too broadly.
Add MFA where possible.
Document the timeline and evidence.

Screenshot Evidence

1.Hydra failed RDP attempts from Kali

<img width="624" height="457" alt="02_hydra_failures" src="https://github.com/user-attachments/assets/4a5c1002-a465-4011-97af-fb280d5619c6" />

2.Raw Splunk timeline showing 4625 failures followed by 4624 success

<img width="624" height="299" alt="02_raw_4625_4624_events" src="https://github.com/user-attachments/assets/6525d5ea-80a1-422f-92be-101a6c202894" />

3.Splunk correlation showing successful login after failures

<img width="624" height="246" alt="02_successful_login_after_failures_detection" src="https://github.com/user-attachments/assets/f797905a-b5db-4f0c-b16c-ba6c8dfb8d95" />

Conclusion

This test proved I can reliably catch a brute force attempt that ends in a compromise.

The lab telemetry showed exactly what I wanted to see the Kali box generated a string of RDP failures against the bwaltz account, followed immediately by a successful logon.

From an analyst perspective, this is the exact moment an alert turns from routine noise into an actual incident. Standard failed logons happen all day, but seeing a success right after a spike in failures means an attacker likely guessed the password or used valid credentials. The investigation has to pivot immediately from monitoring a scanning tool to tracking live post compromise activity on Target-PC.
