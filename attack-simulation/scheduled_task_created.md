# Detection 11: Scheduled Task Created

## Objective

Detect scheduled task creation activity commonly associated with persistence and execution behavior.

This detection identifies the creation of a scheduled task using Windows Security Event ID `4698` and Sysmon Event ID `1`. In this lab, a harmless scheduled task was created using `schtasks.exe` to simulate scheduled task persistence behavior without executing malicious code.

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Persistence | T1053.005 - Scheduled Task/Job: Scheduled Task | A scheduled task was created using `schtasks.exe`. |
| Execution | T1053.005 - Scheduled Task/Job: Scheduled Task | Windows recorded the scheduled task creation event. |

## Log Source

- Windows Security Logs
- Sysmon Operational Logs
- Splunk Universal Forwarder
- Windows Event ID 4698: A scheduled task was created
- Sysmon Event ID 1: Process Creation
- Host: Target-PC

## Detection Logic

This detection looks for scheduled task creation using two telemetry sources:

1. **Windows Security Event ID 4698**  
   Confirms that a scheduled task was created.

2. **Sysmon Event ID 1**  
   Confirms process creation activity involving `schtasks.exe`.

Scheduled tasks are commonly used by administrators for automation, but attackers may also use them for persistence, execution, privilege abuse, or recurring command execution.

## SPL Query

```spl
index=endpoint host="Target-PC" ("Endpoint-Health-Check" OR "schtasks")
| table _time EventCode EventID host ComputerName source Image CommandLine TaskName Message _raw
| sort -_time
```

## Safe Attack Simulation

A harmless scheduled task was created on Target-PC using `schtasks.exe`.

Command used:

```cmd
schtasks /create /tn "\Maintenance\Endpoint-Health-Check" /tr "cmd.exe /c echo Endpoint health check completed > C:\Windows\Temp\endpoint_health_check.txt" /sc once /st 23:59 /f
```

The task name used was:

```text
\Maintenance\Endpoint-Health-Check
```

This task was created for detection validation only. It did not execute malware, download payloads, modify security settings, or create persistence for a malicious tool.

## Detection Result

Splunk detected scheduled task creation activity from Target-PC.

Evidence observed:

```text
Windows Security Event ID: 4698
Message: A scheduled task was created
Task Name: \Maintenance\Endpoint-Health-Check
Host: Target-PC
User: Administrator
```

Sysmon also captured process creation activity involving:

```text
Image: C:\Windows\System32\schtasks.exe
Event ID: 1
CommandLine: schtasks /create ...
```

## Analyst Thought Process

### Initial Alert Meaning

A new scheduled task was created on an endpoint. In a real environment, this could be legitimate administrative activity or attacker behavior used for persistence or recurring execution.

### Key Questions

- Which host created the scheduled task?
- Which user created the task?
- What command or action does the task execute?
- Is the task name consistent with normal administrative activity?
- Was the task created during a normal change window?
- Did the same host show suspicious PowerShell, credential access, downloads, or event log clearing?
- Is the scheduled task configured to run repeatedly, at logon, or with elevated privileges?

### Evidence Reviewed

- Windows Security Event ID 4698
- Sysmon Event ID 1 process creation
- Task name
- Task content
- `schtasks.exe` command line
- Hostname
- User context
- Raw event data

## Analyst Investigation Summary

A scheduled task named `\Maintenance\Endpoint-Health-Check` was created on Target-PC using `schtasks.exe`. Windows Security logs recorded Event ID `4698`, confirming that a scheduled task was created. Sysmon also recorded Event ID `1`, showing process creation activity for `schtasks.exe`.

The task action was benign and wrote a simple text output to `C:\Windows\Temp\endpoint_health_check.txt`. The purpose of this test was to validate scheduled task creation telemetry and detection logic in Splunk.

In a real SOC investigation, this activity would require validation of the task action, user context, timing, parent process, and surrounding endpoint activity.

## Severity

Medium

Scheduled task creation is not always malicious, but it is commonly abused for persistence and recurring execution. Severity increases when the task runs suspicious commands, executes from unusual paths, launches PowerShell, downloads files, runs under privileged accounts, or appears after suspicious authentication activity.

## False Positive Considerations

- Authorized administrator automation
- Software deployment tools
- Endpoint management platforms
- Patch management tasks
- Backup agents
- Monitoring agents
- IT maintenance scripts
- Lab-generated simulation activity

This detection becomes more suspicious when paired with suspicious PowerShell, encoded commands, LSASS access, new services, event log clearing, or Defender tampering.

## Recommended Response

- Identify the affected host.
- Identify the user who created the task.
- Review the scheduled task name, trigger, and action.
- Determine whether the task was authorized.
- Review the command executed by the task.
- Check the parent process and surrounding process activity.
- Search for similar scheduled tasks across the environment.
- Review endpoint logs for related suspicious activity.
- Disable or delete the task if confirmed malicious.
- Isolate the host if the task appears connected to active compromise.
- Document findings and escalate if persistence is suspected.

## Cleanup

After validation, the scheduled task was removed using:

```cmd
schtasks /delete /tn "\Maintenance\Endpoint-Health-Check" /f
```

## Validation Evidence

| Evidence | Screenshot |
|---|---|
| Scheduled task creation command and query confirmation | <img width="624" height="158" alt="11_schtasks_creation_command" src="https://github.com/user-attachments/assets/726dd9e0-f1ea-4054-9186-5b385863252e" /> |
| Windows Security Event ID 4698 showing scheduled task creation | <img width="624" height="387" alt="11_raw_4698_scheduled_task_created" src="https://github.com/user-attachments/assets/79835ffb-d701-40ac-a69e-75ee0a359702" />|
| Sysmon Event ID 1 showing `schtasks.exe` process creation | <img width="624" height="238" alt="11_scheduled_task_detection" src="https://github.com/user-attachments/assets/1228d70b-fc5d-49f2-afbe-bfacebbbece8" /> |

## Analyst Conclusion

This detection successfully identified scheduled task creation activity using Windows Security Event ID `4698` and Sysmon Event ID `1`. The lab safely simulated scheduled task persistence behavior using a benign task name and harmless task action.

Scheduled task creation is important to investigate because attackers commonly use scheduled tasks to maintain persistence, execute commands, or run payloads at specific times or triggers. In a real investigation, the task action, trigger, user context, parent process, and surrounding endpoint activity would determine whether the activity was legitimate or malicious.
