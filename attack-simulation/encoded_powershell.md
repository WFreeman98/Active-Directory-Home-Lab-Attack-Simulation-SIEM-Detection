Detection 6 Encoded PowerShell

Objective
Detect PowerShell running with an encoded command.

This detection uses Sysmon process creation logs from Target-PC.
The main event used for this detection is Sysmon Event ID 1.

Encoded PowerShell is not always malicious.
It still needs to be reviewed because attackers often use it to hide command content.

Lab Setup
Host: Target-PC
SIEM: Splunk
Log Source: Sysmon
Event ID: 1
Process: powershell.exe

MITRE ATT&CK
Execution: T1059.001 - PowerShell
Defense Evasion: T1027 - Obfuscated Files or Information

Detection Logic
Look for PowerShell process creation events where the command line contains encoded execution flags.

Common indicators:
EncodedCommand
-EncodedCommand
-enc
powershell.exe
pwsh.exe

SPL Search
index=endpoint host="Target-PC" ("EncodedCommand" OR "-EncodedCommand" OR " -enc ")
| table _time host ComputerName source EventCode EventID Image ParentImage CommandLine User
| sort -_time

Safe Lab Simulation
A safe encoded PowerShell command was executed on Target-PC.

PowerShell commands:
$cmd = 'Write-Output "SOC Lab Encoded PowerShell Test"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -NoProfile -EncodedCommand $encoded

Expected output:
SOC Lab Encoded PowerShell Test

This command was safe.
It did not download files.
It did not create persistence.
It did not disable Defender.
It did not modify the system.
It was only used to generate Sysmon telemetry for the lab.

Detection Result
Splunk returned a Sysmon Event ID 1 process creation event from Target-PC.

The event showed:
Host: Target-PC
Source: Microsoft-Windows-Sysmon/Operational
Event ID: 1
Process: powershell.exe
Command line: powershell.exe -NoProfile -EncodedCommand

Analyst Review
The first thing I checked was whether the event was real process execution and not just a keyword match.
Sysmon Event ID 1 confirmed that powershell.exe actually ran on Target-PC.

The important fields were:
Host
User
Image
ParentImage
CommandLine
EventID
Source

The command line showed EncodedCommand, which means the actual PowerShell content was Base64 encoded.
In a real investigation, the next step would be to decode the payload and review what it attempted to do.

Investigation Questions I asked myself

1.What host ran PowerShell?

2.What user ran the command?

3.What parent process launched PowerShell?

4.Was the encoded command decoded?

5.Did the decoded command download anything?

6.Did it create a file?

7.Did it start another process?

8.Did it connect to the network?

9.Was there any follow on persistence

Severity
Medium

Raise to High if:
PowerShell was launched by Office, a browser, or an unknown process.
The decoded command downloads remote content.
The command disables Defender or logging.
The command creates persistence.
The command touches credentials or LSASS.
The activity is tied to a suspicious user or host.

False Positives
Admin scripts
Software deployment tools
Security testing
Endpoint management tools
Lab validation
Automation jobs

Tuning Notes
This search is broad on purpose for lab testing.
In production, I would tune it by checking the parent process, user context, host role, and decoded payload.

Good tuning ideas:
Allowlist approved admin scripts.
Allowlist known software deployment tools.
Alert higher when the parent process is suspicious.
Alert higher when encoded PowerShell is followed by network connections.
Alert higher when encoded PowerShell creates files or starts another process.

Recommended Response to this alert

1.Identify the host and user.

2.Decode the Base64 payload.

3.Review the parent process.

4.Check for network connections after execution.

5.Check for new files created after execution.

6.Search for child processes launched by PowerShell.

7.Review related Sysmon and Windows Security events.

8.Confirm whether the activity was authorized.

9.Isolate the host if malicious behavior is confirmed.

10.Document the decoded command and timeline.

Validation Evidence

1.Safe encoded PowerShell command executed on Target-PC
<img width="624" height="125" alt="06_encoded_powershell_execution" src="https://github.com/user-attachments/assets/22cad9dc-9483-4dab-ac94-087b1fa61372" />

2.Raw Sysmon Event ID 1 showing encoded PowerShell activity
<img width="624" height="167" alt="06_raw_sysmon_eventid1_encoded_powershell" src="https://github.com/user-attachments/assets/8062e3dd-b649-4722-9124-bd65545d5ff6" />

3.Splunk detection showing EncodedCommand execution
<img width="624" height="170" alt="06_encoded_powershell_detection" src="https://github.com/user-attachments/assets/1797a798-9b2d-4b5a-8a74-182e575e0147" />

Analyst Conclusion
This detection confirmed encoded PowerShell execution on Target-PC using Sysmon Event ID 1.

The command used in the lab was intentionally safe, but the detection is still valuable because encoded PowerShell is commonly used to hide the real command being executed. The important part of the investigation is not just seeing EncodedCommand. The important part is decoding the payload, checking the parent process, and reviewing what happened after PowerShell ran.

In this lab, Splunk showed the PowerShell process creation event and captured the encoded command in the command line. In a real SOC investigation, I would treat this as suspicious until the decoded command and surrounding activity proved it was authorized.
