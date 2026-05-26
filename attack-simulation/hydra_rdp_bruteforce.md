RDP Brute Force Detection

The Purpose of this was to detect repeated failed RDP authentication attempts against a windows domain workstation.

This detection was tested in the Active Directory lab by sending repeated RDP login attempts from Kali to Target-PC.

Target account: bwaltz
Target host: Target-PC
Attacker host: Kali
Attacker IP: 192.168.10.250
Target service: RDP
Main event: Windows Security Event ID 4625


MITRE Mapping

Credential Access
T1110 Brute Force
Multiple failed logons were created against the same domain user from the same source IP.

Lateral Movement
T1021.001 Remote Services Remote Desktop Protocol
The failed authentication activity targeted RDP on the Windows workstation.


Log Sources

Windows Security Logs
Splunk Universal Forwarder
Splunk index: endpoint
Event ID: 4625
Host: Target-PC


Detection Notes

RDP authentication can show up differently depending on how NLA handles the logon attempt.

In this lab, the failed RDP attempts showed up as Logon Type 3.

Logon Type 3 usually means network-based authentication.
Logon Type 10 usually means RemoteInteractive RDP logon.

The detection checks for both because RDP/NLA activity may not always appear the same way across every system.


Splunk Search

index=endpoint host="Target-PC" EventCode=4625
| eval source_ip=coalesce(Source_Network_Address, IpAddress, Workstation_Name)
| eval user=coalesce(Account_Name, TargetUserName)
| search user="bwaltz"
| where Logon_Type=3 OR Logon_Type=10 OR Logon_Type="3" OR Logon_Type="10"
| stats count earliest(_time) as first_seen latest(_time) as last_seen by source_ip user host ComputerName Logon_Type
| where count >= 5
| convert ctime(first_seen) ctime(last_seen)
| sort -count


Attack Simulation

Hydra was used from Kali to generate failed RDP authentication attempts against Target-PC.

Kali command

hydra -l bwaltz -P passwords_wrong.txt rdp://192.168.10.100 -V

The password file only contained incorrect passwords.

The goal was not to compromise the account.
The goal was to create failed authentication telemetry and validate that Splunk could detect it.


Expected Result

Target-PC should generate multiple Windows Security Event ID 4625 failed logon events.

Important fields to review

Account Name
TargetUserName
Source Network Address
IpAddress
Workstation Name
Logon Type
Failure Reason
host
ComputerName
time


What I Checked

Confirmed Event ID 4625 was present in Splunk.

Confirmed the target account was bwaltz.

Confirmed the affected host was Target-PC.

Confirmed the source IP matched the Kali attacker machine.

Confirmed the failed attempts were repeated and not a single bad password attempt.

Confirmed the logon type was network-based and consistent with RDP/NLA behavior.

Confirmed the detection grouped events by source IP, user, host, and logon type.


Analyst Review

The activity showed multiple failed authentication attempts against the same domain user from the same source IP.

That pattern is stronger than one failed login because it shows repeated guessing behavior.

The first thing I would check after this alert is whether the same user had a successful Event ID 4624 logon after the failed attempts.

If a successful logon happened after the brute force activity, the severity should increase because the account may have been compromised.

I would also check whether the same source IP targeted other users or other hosts.

If the source IP only targeted one user, it may be password guessing against a known account.

If the source IP targeted many users, it may be password spraying.

If the source IP targeted many hosts, it may be lateral movement or automated scanning.


Follow-Up Search

index=endpoint host="Target-PC" (EventCode=4625 OR EventCode=4624)
| eval source_ip=coalesce(Source_Network_Address, IpAddress, Workstation_Name)
| eval user=coalesce(Account_Name, TargetUserName)
| search user="bwaltz"
| table _time EventCode user source_ip host ComputerName Logon_Type
| sort _time


Severity

Medium

Raise to High if Event ID 4624 successful logon occurs from the same source IP and same user after the failed attempts.

Raise to High if the same source IP targets multiple accounts or multiple systems.

Raise to High if follow on activity appears after authentication, such as PowerShell execution, new user creation, privileged group change, scheduled task creation, or new service installation.


False Positives

User typed the wrong password several times.

Saved credentials were outdated.

A service or scheduled task used an old password.

An administrator was testing authentication.

A scanner or vulnerability tool triggered RDP/NLA failures.

Lab testing created expected failed logons.


Tuning Notes

This search is built for lab validation first.

In a real environment I would tune it by adding a time window, excluding known admin testing systems, and reviewing normal authentication patterns.

I would not alert on one failed login.

I would alert when failures repeat from the same source IP against the same account, or when the activity is followed by a successful login.


Response Notes

Identify the source IP.

Confirm whether the source IP is expected.

Review the targeted account.

Check for Event ID 4624 successful logons after the failures.

Check if other users were targeted.

Check if other hosts were targeted.

Review PowerShell, process creation, account creation, group changes, scheduled tasks, and service creation after the login window.

Reset the account password if compromise is suspected.

Restrict RDP access where possible.

Document the timeline.


Validation Evidence

Hydra attack from Kali

<img width="500" alt="hydra_attack" src="https://github.com/user-attachments/assets/ed55f93f-fda6-420c-b93b-ca620abec180" />

Raw Event ID 4625 failed logons

<img width="500" alt="raw_4625_events" src="https://github.com/user-attachments/assets/938e1144-c209-477c-9e75-e5e32162fbfd" />

Splunk detection query result

<img width="500" alt="rdp_bruteforce_detection" src="https://github.com/user-attachments/assets/c0845c17-2ed6-4aef-9ae5-7537ac553b15" />


Conclusion

This detection successfully found repeated failed authentication attempts against the domain user bwaltz on Target-PC.

The activity came from 192.168.10.250, which matched the Kali attacker machine used during testing.

The events were recorded as Windows Security Event ID 4625 with Logon Type 3.

That matches network-based authentication activity and is consistent with RDP/NLA failed logons in this lab.

The detection should be treated as suspected brute force behavior until follow-up investigation confirms whether the account was successfully accessed.

The most important next step is to search for Event ID 4624 from the same source IP and same user.

If a successful logon is found after the failed attempts, the investigation should move from attempted brute force to possible account compromise.
