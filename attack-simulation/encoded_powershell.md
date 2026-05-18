# Detection 06: Encoded PowerShell

## Objective

Detect encoded PowerShell execution using Sysmon process creation telemetry.

This detection identifies PowerShell commands using `-EncodedCommand`, which may indicate command obfuscation or suspicious script execution. In this lab, a safe encoded PowerShell command was executed on Target-PC and detected in Splunk using Sysmon Event ID `1`.

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Execution | T1059.001 - Command and Scripting Interpreter: PowerShell | `powershell.exe` executed with the `-EncodedCommand` argument. |
| Defense Evasion | T1027 - Obfuscated Files or Information | The PowerShell command was Base64-encoded before execution. |

## Log Source

- Sysmon Operational Logs
- Splunk Universal Forwarder
- Sysmon Event ID 1
- Host: Target-PC

## Detection Logic

This detection looks for PowerShell process creation events where the command line contains encoded execution flags such as `EncodedCommand` or `-EncodedCommand`.

Encoded PowerShell is not automatically malicious, but it is commonly used by attackers to hide command contents, bypass basic visibility, or execute obfuscated scripts. In this lab, the encoded command was safe and only printed a test message.

## SPL Query

```spl
index=endpoint host="Target-PC" ("EncodedCommand" OR "-EncodedCommand")
| table _time host ComputerName source EventCode EventID _raw
| sort -_time
```

## Attack Simulation

A safe encoded PowerShell command was executed on Target-PC.

PowerShell commands used:

```powershell
$cmd = 'Write-Output "SOC Lab Encoded PowerShell Test"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -NoProfile -EncodedCommand $encoded
```

Expected output:

```text
SOC Lab Encoded PowerShell Test
```

This command did not download files, create persistence, disable security tools, or modify the system. It was used only to generate safe Sysmon telemetry for detection validation.

## Detection Result

Splunk detected Sysmon Event ID `1` from Target-PC showing `powershell.exe` executed with the `-EncodedCommand` argument.

The event showed:

```text
Host: Target-PC
Source: Microsoft-Windows-Sysmon/Operational
Event ID: 1
Process: powershell.exe
Command line: powershell.exe -NoProfile -EncodedCommand ...
```

## Analyst Thought Process

### Initial Alert Meaning

PowerShell executed with an encoded command. This may indicate suspicious or obfuscated command execution, especially if the encoded content is unknown or tied to other suspicious activity.

### Key Questions

- Which host executed the encoded PowerShell command?
- Which user ran the command?
- What parent process launched PowerShell?
- What was contained in the encoded command?
- Did the command download or execute additional payloads?
- Did this activity occur with other suspicious process or network events?

### Evidence Reviewed

- Sysmon Event ID 1
- Host: Target-PC
- Process: powershell.exe
- Command line containing `-EncodedCommand`
- Safe decoded command output: `SOC Lab Encoded PowerShell Test`

## Analyst Investigation Summary

I began by executing a safe encoded PowerShell command on Target-PC. The command only printed a test message and was used to generate detection telemetry.

After execution, I searched Splunk for Sysmon process creation events containing `EncodedCommand`. Splunk returned a Sysmon Event ID `1` event from Target-PC. The raw event showed that `powershell.exe` executed with the `-EncodedCommand` argument.

In a real SOC investigation, I would decode the Base64 payload to determine what the command attempted to do. I would also review the parent process, user context, network connections, file creation events, and any related PowerShell or Sysmon activity.

## Severity

Medium

Increase to High if the encoded command downloads files, executes remote content, disables security controls, creates persistence, or runs from an unusual parent process.

## False Positive Considerations

- Administrator automation
- Software deployment scripts
- Security testing
- System management tools
- Lab-generated validation activity

This detection becomes more suspicious when PowerShell is launched by Office applications, browsers, unknown executables, or when it is followed by network connections, file writes, or credential access behavior.

## Recommended Response

- Identify the host and user that executed the command.
- Decode the Base64 PowerShell payload.
- Review the parent process.
- Check for network connections after execution.
- Search for related file creation or process execution events.
- Determine whether the command was authorized.
- Isolate the host if malicious behavior is confirmed.
- Document the decoded command and full timeline.

## Validation Evidence

| Evidence | Screenshot |
|---|---|
| Safe encoded PowerShell command executed on Target-PC | <img width="624" height="125" alt="06_encoded_powershell_execution" src="https://github.com/user-attachments/assets/22cad9dc-9483-4dab-ac94-087b1fa61372" /> |
| Raw Sysmon Event ID 1 showing encoded PowerShell activity | <img width="624" height="167" alt="06_raw_sysmon_eventid1_encoded_powershell" src="https://github.com/user-attachments/assets/8062e3dd-b649-4722-9124-bd65545d5ff6" /> |
| Splunk detection showing EncodedCommand execution | <img width="624" height="170" alt="06_encoded_powershell_detection" src="https://github.com/user-attachments/assets/1797a798-9b2d-4b5a-8a74-182e575e0147" /> |

## Analyst Conclusion

This detection successfully identified encoded PowerShell execution on Target-PC using Sysmon Event ID `1`. The command was intentionally safe and generated for lab validation, but the same detection logic can identify suspicious encoded PowerShell activity in a real SOC environment.

Encoded PowerShell should be reviewed carefully because attackers often use it to hide command contents or execute obfuscated scripts. The next investigation steps would be to decode the payload, review the parent process, and check for related network, file, or persistence activity.
