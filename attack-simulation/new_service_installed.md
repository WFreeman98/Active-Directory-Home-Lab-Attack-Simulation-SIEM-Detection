# Detection 12: New Service Installed

## Objective

Detect new Windows service installation activity commonly associated with persistence, execution, and privilege abuse.

This detection identifies service creation using Windows System Event ID `7045` and Sysmon Event ID `1`. In this lab, a harmless service was created using `sc.exe` to simulate Windows service creation behavior without executing malware or establishing malicious persistence.

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Persistence | T1543.003 - Create or Modify System Process: Windows Service | A new Windows service was created using `sc.exe`. |
| Privilege Escalation | T1543.003 - Create or Modify System Process: Windows Service | Windows service creation can be abused to run commands with elevated privileges. |

## Log Source

- Windows System Logs
- Sysmon Operational Logs
- Splunk Universal Forwarder
- Windows System Event ID 7045: A service was installed in the system
- Sysmon Event ID 1: Process Creation
- Host: Target-PC

## Detection Logic

This detection looks for new Windows service creation using two telemetry sources:

1. **Windows System Event ID 7045**  
   Confirms that a service was installed on the system.

2. **Sysmon Event ID 1**  
   Confirms process creation activity involving `sc.exe`.

Windows services are commonly used for legitimate administration, but attackers may also create services for persistence, execution, privilege escalation, or lateral movement.

## SPL Query

```spl
index=endpoint host="Target-PC" ("EndpointInventorySvc" OR "sc.exe")
| table _time EventCode EventID host ComputerName source Service_Name Service_File_Name Image CommandLine Account_Name User Message _raw
| sort -_time
```

## Safe Attack Simulation

A harmless service named `EndpointInventorySvc` was created on Target-PC using `sc.exe`.

Command used:

```cmd
sc.exe create EndpointInventorySvc binPath= "C:\Windows\System32\cmd.exe /c echo Endpoint inventory service check > C:\Windows\Temp\endpoint_inventory_service.txt" start= demand
```

The service name used was:

```text
EndpointInventorySvc
```

This service was created for detection validation only. It did not execute malware, download payloads, disable security controls, or establish malicious persistence.

## Detection Result

Splunk detected new service installation activity from Target-PC.

Evidence observed:

```text
Windows System Event ID: 7045
Message: A service was installed in the system
Service Name: EndpointInventorySvc
Service File Name: C:\Windows\System32\cmd.exe /c echo Endpoint inventory service check > C:\Windows\Temp\endpoint_inventory_service.txt
Host: Target-PC
```

Sysmon also captured process creation activity involving:

```text
Image: C:\Windows\System32\sc.exe
Event ID: 1
CommandLine: sc.exe create EndpointInventorySvc ...
```

## Analyst Thought Process

### Initial Alert Meaning

A new service was installed on an endpoint. In a real environment, this could be legitimate administrative activity or attacker behavior used for persistence, recurring execution, or privilege abuse.

### Key Questions

- Which host installed the service?
- Which user created the service?
- What binary or command does the service execute?
- Is the service name consistent with approved software or administration?
- Was the service created during an approved change window?
- Was `sc.exe` launched from an expected parent process?
- Did the same host show suspicious PowerShell, downloads, credential access, Defender tampering, or event log clearing?
- Was the service started after creation?

### Evidence Reviewed

- Windows System Event ID 7045
- Sysmon Event ID 1 process creation
- Service name
- Service file path
- `sc.exe` command line
- Hostname
- User context
- Raw event data

## Analyst Investigation Summary

A service named `EndpointInventorySvc` was created on Target-PC using `sc.exe`. Windows System logs recorded Event ID `7045`, confirming that a service was installed. Sysmon also recorded Event ID `1`, showing process creation activity for `sc.exe`.

The service action was benign and pointed to a simple command that writes text output to `C:\Windows\Temp\endpoint_inventory_service.txt`. The purpose of this test was to validate new service installation telemetry and detection logic in Splunk.

In a real investigation, this activity would require validation of the service binary path, user context, parent process, timing, service start behavior, and surrounding endpoint activity.

## Severity

High

New service installation can be high severity because attackers commonly create services for persistence, execution, privilege escalation, or lateral movement. Severity increases when the service binary runs from unusual paths, launches scripting engines, points to temporary directories, uses suspicious names, or appears after suspicious authentication activity.

## False Positive Considerations

- Authorized administrator activity
- Software installation
- Endpoint management tools
- Patch management agents
- Backup or monitoring agents
- Security tool deployment
- IT maintenance scripts
- Lab-generated simulation activity

This detection becomes more suspicious when paired with suspicious PowerShell, encoded commands, LSASS access, Defender tampering, scheduled task creation, or event log clearing.

## Recommended Response

- Identify the affected host.
- Identify the user who created the service.
- Review the service name, binary path, start type, and account.
- Determine whether the service creation was authorized.
- Review the parent process and surrounding process activity.
- Check whether the service was started.
- Search for the same service name or binary path across the environment.
- Review endpoint logs for related suspicious activity.
- Stop and disable the service if confirmed malicious.
- Isolate the host if the service appears connected to active compromise.
- Preserve logs and document the timeline.
- Escalate if persistence or lateral movement is suspected.

## Cleanup

After validation, the service was removed using:

```cmd
sc.exe delete EndpointInventorySvc
```

## Validation Evidence

| Evidence | Screenshot |
|---|---|
| Service creation command and service query confirmation | <img width="624" height="154" alt="12_service_creation_command" src="https://github.com/user-attachments/assets/57301e94-860e-4fad-919f-bcd91cdf5a9f" /> |
| Windows System Event ID 7045 showing new service installation | <img width="624" height="175" alt="12_raw_7045_new_service_installed" src="https://github.com/user-attachments/assets/ceda9448-6a5f-4af5-b707-26f636faff8a" /> |
| Sysmon Event ID 1 showing `sc.exe` process creation | <img width="624" height="230" alt="12_new_service_detection" src="https://github.com/user-attachments/assets/f791aa99-a3fa-4ce2-8a6e-125ebc0dff33" /> |

## Analyst Conclusion

This detection successfully identified new Windows service installation activity using Windows System Event ID `7045` and Sysmon Event ID `1`. The lab safely simulated service creation using a benign service name and harmless service action.

In my conclusion, new service installation is an important endpoint behavior to investigate because services can be used for legitimate administration or abused for persistence, execution, privilege escalation, and lateral movement. This detection validated that Windows System Event ID 7045 can confirm service installation, while Sysmon Event ID 1 can show the process and command line used to create it. In a real investigation, I would review the service name, binary path, user context, parent process, start type, and related endpoint activity to determine whether the activity was authorized or suspicious.
