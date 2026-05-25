# Detection 10: Defender Tampering

## Objective

Detect command-line activity associated with Microsoft Defender tampering behavior.

This detection identifies suspicious PowerShell command-line indicators commonly associated with attempts to disable or modify Microsoft Defender protections. In this lab, a safe command line simulation was used to generate Sysmon Event ID `1` telemetry without actually disabling Defender or changing security settings.

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Defense Evasion | T1562.001 - Impair Defenses: Disable or Modify Tools | PowerShell command line contained Microsoft Defender tampering indicators. |

## Log Source

- Sysmon Operational Logs
- Splunk Universal Forwarder
- Sysmon Event ID 1: Process Creation
- Host: Target-PC

## Detection Logic

This detection looks for Sysmon process creation events where the command line contains Microsoft Defender tampering indicators such as:

```text
Set-MpPreference
DisableRealtimeMonitoring
Add-MpPreference
ExclusionPath
DisableBehaviorMonitoring
```

Attackers may attempt to disable security tools, modify Microsoft Defender settings, or add exclusions to prevent malware, tools, or scripts from being detected.

## SPL Query

```spl
index=endpoint host="Target-PC" source="*Sysmon*" EventCode=1
("DisableRealtimeMonitoring" OR "Set-MpPreference" OR "Add-MpPreference" OR "ExclusionPath" OR "DisableBehaviorMonitoring")
| table _time EventCode host ComputerName Image CommandLine ParentImage User
| sort -_time
```

## Safe Attack Simulation

A safe simulation command was executed on Target-PC to generate Defender tampering-style command-line telemetry.

Command used:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SIMULATION: Set-MpPreference -DisableRealtimeMonitoring True'"
```

This command did **not** disable Microsoft Defender, add exclusions, or modify security settings. It only generated command-line evidence for detection validation.

## Detection Result

Splunk detected a Sysmon Event ID `1` process creation event from Target-PC.

The event showed:

```text
Event ID: 1
Host: Target-PC
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SIMULATION: Set-MpPreference -DisableRealtimeMonitoring True'"
```

## Analyst Thought Process

### Initial Alert Meaning

The command line contained Microsoft Defender tampering indicators. In a real environment, this could indicate an attacker attempting to disable endpoint protection, reduce detection coverage, or create exclusions for malicious tools.

### Key Questions

- Which host executed the command?
- Which user launched the process?
- Was Microsoft Defender actually modified?
- Was the command part of authorized administration or testing?
- Did the same host show suspicious PowerShell, downloads, credential access, or persistence activity?
- Were any Defender exclusions added?
- Did endpoint protection generate related alerts?

### Evidence Reviewed

- Sysmon Event ID 1 process creation
- Host: Target-PC
- Image: powershell.exe
- CommandLine containing `Set-MpPreference` and `DisableRealtimeMonitoring`
- Parent process
- User context
- Raw Sysmon event data

## Analyst Investigation Summary

I generated a safe Defender tampering simulation on Target-PC using PowerShell. The command included Defender tampering keywords but did not actually disable Defender or change security settings.

After running the simulation, I searched Splunk for Sysmon Event ID `1` process creation events containing Defender tampering indicators. Splunk returned a matching Sysmon event showing PowerShell execution with `Set-MpPreference` and `DisableRealtimeMonitoring` in the command line.

In a real SOC investigation, this alert would require immediate validation to determine whether Defender protections were actually disabled, exclusions were added, or the activity was part of a broader attack chain.

## Severity

High

Defender tampering should be treated as high severity because attackers commonly attempt to disable security controls before executing malware, dumping credentials, maintaining persistence, or moving laterally.

## False Positive Considerations

- Authorized administrator testing
- Security team validation
- Endpoint management scripts
- Troubleshooting by IT staff
- Lab-generated simulation activity
- Approved configuration management tools

This detection becomes more suspicious when paired with encoded PowerShell, suspicious downloads, LSASS access, new services, scheduled tasks, or event log clearing.

## Recommended Response

- Identify the affected host and user.
- Confirm whether Defender settings were actually modified.
- Review Microsoft Defender event logs and security alerts.
- Check for exclusions, disabled protections, or policy changes.
- Review surrounding PowerShell and process creation activity.
- Search for related suspicious activity such as downloads, credential access, persistence, or lateral movement.
- Isolate the host if malicious activity is suspected.
- Re-enable protections if they were disabled.
- Reset credentials if account compromise is suspected.
- Document the full timeline and escalation actions.

## Validation Evidence

| Evidence | Screenshot |
|---|---|
| Safe PowerShell simulation command containing Defender tampering indicators | <img width="646" height="82" alt="10_defender_tampering_simulation_command" src="https://github.com/user-attachments/assets/033f8510-d199-4d7d-a278-085421e5f137" /> |
| Raw Sysmon Event ID 1 showing PowerShell command-line evidence | <img width="624" height="382" alt="10_raw_ sysmon_eventid1_defender_tampering" src="https://github.com/user-attachments/assets/b2f3fb88-7143-4568-a905-58bb0d3ed6ea" /> |
| Splunk detection query identifying Defender tampering indicators | <img width="624" height="385" alt="10_defender_tampering_detection" src="https://github.com/user-attachments/assets/9e1fea3b-2541-45e4-8aa6-0bb9d4476615" /> |

## Analyst Conclusion

This detection successfully identified Defender tampering style command-line activity using Sysmon Event ID `1` and Splunk. The test was safely simulated and did not modify Microsoft Defender settings.

This detection is important because disabling or modifying security tools is a common defense evasion technique. In a real investigation, the next step would be to verify whether Defender settings were changed and determine whether the activity was part of a larger compromise.
