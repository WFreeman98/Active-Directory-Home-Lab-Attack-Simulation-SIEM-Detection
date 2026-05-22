# Detection 08: LSASS Access / Credential Dumping Behavior

## Objective

Detect suspicious process access to `lsass.exe` using Sysmon ProcessAccess telemetry.

This detection identifies Sysmon Event ID `10`, which is generated when one process accesses another process. In this lab, a safe PowerShell-based LSASS access simulation was used to generate telemetry showing access to `lsass.exe`.

No credentials were dumped or extracted. The purpose of this test was to safely validate detection logic for suspicious LSASS access behavior.

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Credential Access | T1003.001 - OS Credential Dumping: LSASS Memory | A process accessed `lsass.exe`, which is commonly associated with credential dumping behavior. |

## Log Source

- Sysmon Operational Logs
- Splunk Universal Forwarder
- Sysmon Event ID 10
- Host: Target-PC

## Detection Logic

This detection looks for Sysmon Event ID `10` where the target process is `lsass.exe`.

Access to `lsass.exe` is important because attackers commonly target LSASS memory to extract credentials, password hashes, or authentication material. While some legitimate system processes may access LSASS, unusual access from scripting tools, admin tools, or unknown processes should be investigated.

## SPL Query

```spl
index=endpoint host="Target-PC" source="*Sysmon*" "lsass.exe"
| table _time EventCode EventID host ComputerName _raw
| sort -_time
```

## Attack Simulation

A safe LSASS access simulation was performed on Target-PC using PowerShell.

PowerShell command used:

```powershell
$p = [System.Diagnostics.Process]::GetProcessesByName("lsass")[0]
$p.Handle
```

This command opened a handle to the LSASS process and generated Sysmon ProcessAccess telemetry.

This test did **not** dump LSASS memory, create a dump file, run Mimikatz, extract credentials, or save credential material. It was used only to safely generate Sysmon Event ID `10`.

## Detection Result

Splunk detected Sysmon Event ID `10` showing process access to `lsass.exe`.

The event showed:

```text
Host: Target-PC
Source: Microsoft-Windows-Sysmon/Operational
Event ID: 10
SourceImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetImage: C:\Windows\System32\lsass.exe
```

## Analyst Thought Process

### Initial Alert Meaning

A process accessed `lsass.exe`. This may indicate credential dumping behavior, especially if the source process is unusual, user launched, or associated with offensive tooling.

### Key Questions

- What process accessed `lsass.exe`?
- What user context was involved?
- Was the source process expected or suspicious?
- What level of access was requested?
- Was a dump file created?
- Were there related process, file, or command line events?
- Did the activity happen after a successful logon or privilege change?

### Evidence Reviewed

- Sysmon Event ID 10
- Target process: `lsass.exe`
- Source process: `powershell.exe`
- Host: Target-PC
- Raw Sysmon ProcessAccess event
- GrantedAccess field
- CallTrace field

## Analyst Investigation Summary

I began by confirming that Sysmon ProcessAccess logging was enabled for `lsass.exe`. After applying the Sysmon configuration, I performed a safe LSASS access simulation from PowerShell on Target PC.

I then searched Splunk for Sysmon events containing `lsass.exe`. Splunk returned Sysmon Event ID `10`, showing that `powershell.exe` accessed `lsass.exe`. The raw event confirmed the target image was `C:\Windows\System32\lsass.exe`.

In a real SOC investigation, I would treat this as suspicious until proven legitimate. I would review the source process, user context, parent process, command line activity, and any file creation events that could indicate LSASS memory dumping. I would also check for related account compromise indicators, privileged group changes, or follow-on lateral movement.

## Severity

High

Access to `lsass.exe` should be treated as high severity when performed by unusual processes, scripting tools, credential access tools, or unknown binaries.

## False Positive Considerations

- Antivirus or EDR tools inspecting LSASS
- Backup or security monitoring software
- Legitimate system processes
- Administrator troubleshooting
- Lab-generated validation activity

This detection becomes more suspicious when LSASS is accessed by PowerShell, command-line tools, unknown executables, temporary directory binaries, or tools commonly associated with credential dumping.

## Recommended Response

- Identify the source process that accessed `lsass.exe`.
- Review the user account and host involved.
- Check the parent process and command line.
- Search for dump file creation or suspicious file writes.
- Review related Sysmon Event ID 1 process creation events.
- Check for successful logons, privileged group changes, or lateral movement.
- Isolate the host if credential dumping is suspected.
- Reset affected credentials if compromise is confirmed.
- Document the full investigation timeline.

## Validation Evidence

| Evidence | Screenshot |
|---|---|
| Safe PowerShell LSASS access simulation | <img width="624" height="40" alt="08_safe_lsass_access_simulation" src="https://github.com/user-attachments/assets/166816e9-365d-49d6-a40c-b0bdfcecca42" /> |
| Raw Sysmon Event ID 10 showing ProcessAccess to LSASS | <img width="624" height="262" alt="08_raw_sysmon_eventid10_lsass_access" src="https://github.com/user-attachments/assets/1982257e-534f-4c9e-982a-2e75fad0b5af" /> |
| Splunk detection showing LSASS access behavior | <img width="624" height="40" alt="08_safe_lsass_access_simulation" src="https://github.com/user-attachments/assets/beea1e96-f2fd-4ca3-8f34-da5a4af1ff0c" /> |

## Analyst Conclusion

This detection successfully identified process access to `lsass.exe` using Sysmon Event ID `10`. The activity was safely generated using PowerShell to validate ProcessAccess telemetry without dumping credentials.

This detection is important because suspicious access to LSASS is commonly associated with credential dumping. In a real SOC investigation, this alert would require immediate review of the source process, user context, related process activity, and any evidence of credential theft or follow-on attacker behavior.
