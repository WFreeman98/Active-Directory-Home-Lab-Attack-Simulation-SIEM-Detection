Detection 9 Event Log Clearing

Objective
Detect Windows Security event log clearing activity.

This detection uses Windows Security Event ID 1102 from Target-PC.
Event ID 1102 is generated when the Security audit log is cleared.

Security log clearing is high risk because it can remove evidence of failed logons, successful logons, account changes, privilege changes, PowerShell activity, and other attacker behavior.

Lab Setup
Host: Target-PC
SIEM: Splunk
Log Source: Windows Security
Event ID: 1102
Tool Used: wevtutil

MITRE ATT&CK
Defense Evasion: T1070.001 - Clear Windows Event Logs

Detection Logic
Look for Windows Security Event ID 1102.

This event should be rare in normal activity.
In a real environment, clearing the Security log should be reviewed immediately unless there is a known administrative reason.

Important fields:
EventCode
host
ComputerName
Account_Name
Message
_time

SPL Search
index=endpoint host="Target-PC" EventCode=1102
| table _time EventCode host ComputerName Account_Name Message
| sort -_time

Broader Search
index=endpoint EventCode=1102
| table _time EventCode host ComputerName Account_Name Message
| sort -_time

Safe Lab Simulation
The Windows Security log was cleared on Target-PC using an administrator command prompt.

Command used:
wevtutil cl Security

Confirmation command:
echo Security log clear test completed

This generated Windows Security Event ID 1102.

This test was controlled.
It was performed in a lab.
It was only used to validate log clearing detection.
Centralized Splunk logging preserved the evidence even after the local Security log was cleared.

Detection Result
Splunk returned Windows Security Event ID 1102 from Target-PC.

The event showed:
Event ID: 1102
Host: Target-PC
ComputerName: Target-PC.corp.local
Account Name: Administrator
Message: The audit log was cleared.

Analyst Review
The first thing I checked was whether the log clearing event came from the expected host.
Splunk showed Event ID 1102 from Target-PC.

The next thing I checked was the account tied to the event.
The event showed Administrator as the account associated with the clearing activity.

This matters because Security log clearing can be used after suspicious activity to hide evidence.
The event itself tells me the log was cleared, but it does not answer why it was cleared.
That is why the timeline before the event matters more than the event by itself.

Investigation Questions I would ask myself
1.Which host had the Security log cleared?

2.Which account cleared the log?

3.Was the account expected to perform this action?

4.Was this approved maintenance?

5.What happened before the log was cleared?

6.Were there failed logons before the event?

7.Were there successful remote logons before the event?

8.Were there account creations before the event?

9.Were there privileged group changes before the event?

10.Was PowerShell used before the event?

11.Were scheduled tasks or services created before the event?

12.Did the same account perform other administrative actions?

Severity
High

Security log clearing should be treated as high severity unless it is confirmed to be authorized.

Keep High if:
The action happened after failed logons.
The action happened after successful remote access.
The action happened after account creation.
The action happened after privileged group changes.
The action happened after suspicious PowerShell.
The account that cleared the log is unusual.
The clearing happened outside normal maintenance windows.

False Positives
Authorized administrator maintenance
System troubleshooting
Security team testing
Lab validation
Approved log cleanup procedures

Tuning Notes
This detection should not be tuned out too aggressively.
Event ID 1102 is important because Security log clearing is uncommon and high value.

Good tuning ideas:
Track which admins are allowed to clear logs.
Compare the event time to approved maintenance windows.
Correlate with authentication events before the clearing.
Correlate with account management events before the clearing.
Correlate with PowerShell and process creation events before the clearing.
Alert higher when the event follows suspicious activity.

Recommended Response to this alert:
Identify the host where the Security log was cleared.
Identify the account that cleared the log.
Confirm whether the action was authorized.
Review activity before the clearing event.
Search for failed logons before the event.
Search for successful logons before the event.
Search for account creation or privileged group changes.
Search for PowerShell, scheduled tasks, services, and persistence activity.
Preserve available logs from Splunk or other centralized logging.
Isolate the host if malicious activity is suspected.
Reset credentials if account compromise is suspected.
Document the full timeline.

Validation Evidence

1.wevtutil command clearing the Security log on Target-PC
<img width="566" height="151" alt="09_wevtutil_clear_security_log" src="https://github.com/user-attachments/assets/cbbfb315-d0df-4063-a97e-afcde1f0d8e1" />

2.Raw Windows Event ID 1102 showing Security log cleared
<img width="624" height="342" alt="09_raw_1102_security_log_cleared" src="https://github.com/user-attachments/assets/03281f6c-b854-4dc6-b81b-fab7d499ec8a" />

3.Splunk detection showing Event ID 1102 log clearing activity
<img width="624" height="181" alt="09_event_log_clearing_detection" src="https://github.com/user-attachments/assets/aac624b3-7bb6-4784-bfa3-045766d045f7" />

Analyst Conclusion
This detection confirmed Windows Security log clearing on Target-PC using Event ID 1102.

The lab action was performed with wevtutil cl Security, and Splunk captured the event showing that the audit log was cleared. This is an important detection because clearing the Security log can be used to hide earlier attacker activity.

In a real SOC investigation, I would not treat the log clearing event as the full story. I would build a timeline before the clearing event and look for failed logons, successful remote logons, account creation, privileged group changes, suspicious PowerShell, scheduled tasks, service creation, or other activity the user may have tried to hide. Centralized logging is important here because the local logs may be cleared, but the SIEM can still preserve evidence.
