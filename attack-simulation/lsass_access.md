Detection 8 LSASS Access / Credential Dumping Behavior

Objective
Detect suspicious access to lsass.exe using Sysmon ProcessAccess telemetry.

This detection uses Sysmon Event ID 10 from Target-PC.
The goal is to identify when a process opens a handle to LSASS.

LSASS access is high risk because attackers often target LSASS memory for credential dumping.
This lab did not dump credentials.
This lab only generated safe ProcessAccess telemetry.

Lab Setup
Host: Target-PC
SIEM: Splunk
Log Source: Sysmon
Event ID: 10
Target Process: lsass.exe
Source Process: powershell.exe

MITRE ATT&CK
Credential Access: T1003.001 - LSASS Memory

Detection Logic
Look for Sysmon ProcessAccess events where the target process is lsass.exe.

Important fields:
SourceImage
TargetImage
GrantedAccess
CallTrace
User
Host
EventID

Common suspicious source processes:
powershell.exe
cmd.exe
rundll32.exe
procdump.exe
taskmgr.exe
unknown executables
tools running from temp folders

SPL Search
index=endpoint host="Target-PC" source="*Sysmon*" "lsass.exe"
| table _time EventCode EventID host ComputerName SourceImage TargetImage GrantedAccess CallTrace User _raw
| sort -_time

Stronger Search
index=endpoint host="Target-PC" source="*Sysmon*" EventCode=10
| search TargetImage="*lsass.exe"
| table _time host ComputerName User SourceImage TargetImage GrantedAccess CallTrace
| sort -_time

Safe Lab Simulation
A safe LSASS access simulation was performed on Target-PC using PowerShell.

PowerShell command:
$p = [System.Diagnostics.Process]::GetProcessesByName("lsass")[0]
$p.Handle

This opened a handle to the LSASS process.
Sysmon generated Event ID 10 ProcessAccess telemetry.

This test was safe.
It did not dump LSASS memory.
It did not create a dump file.
It did not run Mimikatz.
It did not extract credentials.
It did not save credential material.
It was only used to validate Sysmon ProcessAccess logging.

Detection Result
Splunk returned a Sysmon Event ID 10 event from Target-PC.

The event showed:
Host: Target-PC
Source: Microsoft-Windows-Sysmon/Operational
Event ID: 10
SourceImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetImage: C:\Windows\System32\lsass.exe

Analyst Review
The first thing I checked was whether the event showed real process access to LSASS.
Sysmon Event ID 10 confirmed that a source process accessed lsass.exe.

The source process was PowerShell.
That matters because PowerShell accessing LSASS is not something I would treat as normal without more context.

The most important fields were:
SourceImage
TargetImage
GrantedAccess
CallTrace
User
Host
ComputerName
EventID

In a real SOC investigation, I would review the GrantedAccess value and CallTrace to understand the type of access requested.
I would also check whether the same host created a dump file or launched any known credential dumping tools.

Investigation Questions I asked myself

1.What process accessed LSASS?

2.What user context was involved?

3.Was the source process expected?

4.Was the source process signed and in a normal path?

5.What level of access was requested?

6.Was a dump file created?

7.Was there related process creation activity?

8.Was there related file creation activity?

9.Did this happen after a successful suspicious logon?

10.Did the same user make privileged group changes?

11.Was there lateral movement after this event?

Severity
High

LSASS access should be reviewed quickly.
Raise priority when the source process is unusual, user-launched, running from a temporary folder, or tied to other suspicious activity.

Keep High if:
PowerShell accessed LSASS.
A credential dumping tool accessed LSASS.
A dump file was created.
The source process came from Downloads, Temp, or AppData.
The activity happened after suspicious logon activity.
The host also shows persistence or lateral movement.

False Positives
Antivirus tools
EDR tools
Security monitoring software
Backup tools
Legitimate system processes
Administrator troubleshooting
Lab validation

Tuning Notes
This search is broad on purpose for lab validation.
In production, I would tune by source process, signer, file path, GrantedAccess, and known security tool behavior.

Good tuning ideas:
Allowlist approved EDR and antivirus processes.
Alert higher on PowerShell or command-line tools accessing LSASS.
Alert higher on processes running from Temp, Downloads, or AppData.
Correlate LSASS access with file creation events.
Correlate LSASS access with recent successful logons.
Correlate LSASS access with privileged group changes.
Correlate LSASS access with outbound network connections.

Recommended Response to this alert:
Identify the source process.
Identify the user and host.
Review the parent process and command line.
Check the process path and file reputation.
Review GrantedAccess and CallTrace.
Search for dump file creation.
Review Sysmon Event ID 1 process creation events.
Review Sysmon Event ID 11 file creation events if available.
Check for successful logons before the LSASS access.
Check for privileged group changes or lateral movement.
Isolate the host if credential dumping is suspected.
Reset credentials if compromise is confirmed.
Document the full timeline.

Validation Evidence

1.Safe PowerShell LSASS access simulation
<img width="624" height="40" alt="08_safe_lsass_access_simulation" src="https://github.com/user-attachments/assets/166816e9-365d-49d6-a40c-b0bdfcecca42" />

2.Raw Sysmon Event ID 10 showing ProcessAccess to LSASS
<img width="624" height="262" alt="08_raw_sysmon_eventid10_lsass_access" src="https://github.com/user-attachments/assets/1982257e-534f-4c9e-982a-2e75fad0b5af" />

3.Splunk detection showing LSASS access behavior
<img width="624" height="40" alt="08_safe_lsass_access_simulation" src="https://github.com/user-attachments/assets/beea1e96-f2fd-4ca3-8f34-da5a4af1ff0c" />

Analyst Conclusion
This detection confirmed process access to lsass.exe on Target-PC using Sysmon Event ID 10.

The lab simulation was intentionally safe and did not dump credentials. The value of this detection is that it confirms visibility into LSASS ProcessAccess activity, which is one of the behaviors analysts watch for during credential dumping investigations.

In this lab, PowerShell opened a handle to LSASS and Splunk captured the event. In a real SOC investigation, I would treat this as high risk until the source process, user context, GrantedAccess value, and surrounding activity proved it was expected. The next step would be to look for dump file creation, suspicious child processes, recent successful logons, and any follow-on activity that could indicate credential theft or lateral movement.
