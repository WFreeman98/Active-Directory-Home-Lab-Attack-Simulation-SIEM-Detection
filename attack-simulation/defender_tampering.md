Detection 10 Defender Tampering

Objective
Detect command line activity that looks like Microsoft Defender tampering.

This detection uses Sysmon process creation telemetry from Target-PC.
The main event used for this detection is Sysmon Event ID 1.

The lab used a safe simulation command.
Defender was not disabled.
No exclusions were added.
No security settings were changed.

Lab Setup
Host: Target-PC
SIEM: Splunk
Log Source: Sysmon
Event ID: 1
Process: powershell.exe

MITRE ATT&CK
Defense Evasion: T1562.001 - Disable or Modify Tools

Detection Logic
Look for process creation events where the command line contains Microsoft Defender tampering indicators.

Common indicators:
Set-MpPreference
DisableRealtimeMonitoring
Add-MpPreference
ExclusionPath
DisableBehaviorMonitoring

These keywords matter because attackers may try to weaken endpoint protection before running tools, downloading payloads, dumping credentials, or creating persistence.

SPL Search
index=endpoint host="Target-PC" source="*Sysmon*" EventCode=1
("DisableRealtimeMonitoring" OR "Set-MpPreference" OR "Add-MpPreference" OR "ExclusionPath" OR "DisableBehaviorMonitoring")
| table _time EventCode host ComputerName Image CommandLine ParentImage User
| sort -_time

Safe Lab Simulation
A safe PowerShell command was executed on Target-PC.

Command used:
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SIMULATION: Set-MpPreference -DisableRealtimeMonitoring True'"

This command was safe.
It only printed text.
It did not disable Microsoft Defender.
It did not add exclusions.
It did not change Defender settings.
It was only used to generate command-line telemetry for detection validation.

Detection Result
Splunk returned a Sysmon Event ID 1 process creation event from Target-PC.

The event showed:
Event ID: 1
Host: Target-PC
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SIMULATION: Set-MpPreference -DisableRealtimeMonitoring True'"

Analyst Review
The first thing I checked was whether the event was real process execution.
Sysmon Event ID 1 confirmed that PowerShell ran on Target-PC.

The next thing I checked was the command line.
The command line contained Defender tampering indicators, including Set-MpPreference and DisableRealtimeMonitoring.

In this lab, those words were only printed as part of a safe simulation.
In a real SOC investigation, I would need to verify whether Defender settings were actually changed.

The important fields were:
Host
User
Image
ParentImage
CommandLine
EventID
Source

This detection is useful because command line telemetry can show intent or attempted defense evasion even before the analyst confirms whether the change succeeded.

Investigation Questions I asked myself

1.Which host ran the command?

2.Which user launched PowerShell?

3.What parent process launched PowerShell?

4.Was Defender actually changed?

5.Were any exclusions added?

6.Was real time protection disabled?

7.Was behavior monitoring disabled?

8.Was this part of approved administration?

9.Did the host show encoded PowerShell?

10.Did the host download files before or after this?

11.Did the host show LSASS access?

12.Did the host create scheduled tasks or new services?

13.Was the Security log cleared afterward?

Severity
High

Defender tampering should be treated as high severity until proven authorized.

Keep High if:
Defender settings were actually changed.
Exclusions were added.
PowerShell was launched from an unusual parent process.
The activity happened after a suspicious download.
The activity happened before LSASS access.
The activity happened before persistence.
The same host also had event log clearing.
The user account is not expected to make security changes.

False Positives
Authorized administrator testing
Security team validation
Endpoint management scripts
Troubleshooting by IT staff
Approved configuration management tools
Lab validation

Tuning Notes
This search is broad on purpose for lab validation.
In production, I would tune this by checking whether Defender settings actually changed and by reviewing the user, parent process, and surrounding activity.

Good tuning ideas:
Allowlist approved endpoint management tools.
Allowlist known security team scripts.
Alert higher when PowerShell is launched by Office, browsers, or unknown processes.
Alert higher when Defender tampering follows suspicious downloads.
Alert higher when Defender tampering happens before LSASS access.
Alert higher when exclusions are added for Temp, Downloads, AppData, or unknown tool folders.
Correlate with Defender logs and Sysmon process activity.

Recommended Response for this alert:
Identify the affected host and user.
Review the full PowerShell command line.
Check the parent process.
Confirm whether Defender settings changed.
Check for new Defender exclusions.
Review Microsoft Defender event logs.
Review endpoint security alerts.
Search for related PowerShell activity.
Search for downloads, LSASS access, scheduled tasks, services, or event log clearing.
Re-enable protections if they were disabled.
Isolate the host if malicious behavior is confirmed.
Reset credentials if account compromise is suspected.
Document the full timeline.

Validation Evidence

1.Safe PowerShell simulation command containing Defender tampering indicators
<img width="646" height="82" alt="10_defender_tampering_simulation_command" src="https://github.com/user-attachments/assets/033f8510-d199-4d7d-a278-085421e5f137" />

2.Raw Sysmon Event ID 1 showing PowerShell command-line evidence
<img width="624" height="382" alt="10_raw_ sysmon_eventid1_defender_tampering" src="https://github.com/user-attachments/assets/b2f3fb88-7143-4568-a905-58bb0d3ed6ea" />

3.Splunk detection query identifying Defender tampering indicators
<img width="624" height="385" alt="10_defender_tampering_detection" src="https://github.com/user-attachments/assets/9e1fea3b-2541-45e4-8aa6-0bb9d4476615" />

Analyst Conclusion
This detection confirmed Defender tampering-style command-line activity on Target-PC using Sysmon Event ID 1.

The lab command was intentionally safe and did not modify Microsoft Defender. It only generated command-line evidence that looked like Defender tampering so the detection logic could be validated in Splunk.

This detection matters because attackers often try to weaken security tools before running malware, dumping credentials, or creating persistence. In a real SOC investigation, I would not stop at the keyword match. I would confirm whether Defender settings changed, check for exclusions, review the parent process, and search for related activity before and after the event.
