Detection 12 New Service Installed

Objective
Detect new Windows service installation activity on a Windows endpoint.

This detection uses Windows System Event ID 7045 and Sysmon Event ID 1 from Target-PC.
The goal is to identify when a new service is installed and review what the service is configured to run.

Windows services are normal in enterprise environments.
They still need to be reviewed because attackers can use services for persistence, execution, privilege escalation, or lateral movement.

Lab Setup
Host: Target-PC
SIEM: Splunk
Log Sources: Windows System and Sysmon
Windows System Event ID: 7045
Sysmon Event ID: 1
Tool Used: sc.exe
Service Name: EndpointInventorySvc

MITRE ATT&CK
Persistence: T1543.003 - Windows Service
Privilege Escalation: T1543.003 - Windows Service

Detection Logic
Look for new Windows service installation using both Windows System logs and Sysmon process creation logs.

Windows System Event ID 7045 confirms that a service was installed.
Sysmon Event ID 1 confirms the process and command line used to create the service.

Important indicators:
sc.exe
create
Service_Name
Service_File_Name
Image
CommandLine
ParentImage
User
EventCode 7045
EventCode 1

SPL Search
index=endpoint host="Target-PC" ("EndpointInventorySvc" OR "sc.exe")
| table _time EventCode EventID host ComputerName source Service_Name Service_File_Name Image CommandLine Account_Name User Message _raw
| sort -_time

Windows System Search
index=endpoint host="Target-PC" EventCode=7045
| table _time EventCode host ComputerName Service_Name Service_File_Name Account_Name Message _raw
| sort -_time

Sysmon Process Search
index=endpoint host="Target-PC" source="*Sysmon*" EventCode=1 "sc.exe"
| table _time EventCode EventID host ComputerName Image CommandLine ParentImage User
| sort -_time

Safe Lab Simulation
A harmless service named EndpointInventorySvc was created on Target-PC using sc.exe.

Command used:
sc.exe create EndpointInventorySvc binPath= "C:\Windows\System32\cmd.exe /c echo Endpoint inventory service check > C:\Windows\Temp\endpoint_inventory_service.txt" start= demand

Service name:
EndpointInventorySvc

Cleanup command:
sc.exe delete EndpointInventorySvc

This test was safe.
It did not execute malware.
It did not download payloads.
It did not disable security tools.
It did not establish malicious persistence.
It only created a benign service for detection validation.

Detection Result
Splunk returned new service installation evidence from Target-PC.

Windows System showed:
Event ID: 7045
Message: A service was installed in the system
Service Name: EndpointInventorySvc
Service File Name: C:\Windows\System32\cmd.exe /c echo Endpoint inventory service check > C:\Windows\Temp\endpoint_inventory_service.txt
Host: Target-PC

Sysmon showed:
Event ID: 1
Image: C:\Windows\System32\sc.exe
CommandLine: sc.exe create EndpointInventorySvc ...

Analyst Review
The first thing I checked was whether Windows recorded the service installation.
Windows System Event ID 7045 confirmed that a new service was installed on Target-PC.

The next thing I checked was the process that created the service.
Sysmon Event ID 1 showed sc.exe process creation and captured the command line.

The service name alone is not enough to decide if the activity is malicious.
The service binary path matters more.

In this lab, the service action was benign and only wrote a text file to C:\Windows\Temp.
In a real SOC investigation, I would check whether the service points to PowerShell, cmd, rundll32, regsvr32, a suspicious executable, a user-writable folder, or a remote path.

Important fields:
Host
User
Service_Name
Service_File_Name
Image
CommandLine
ParentImage
Account_Name
EventCode
EventID
_time

Investigation Questions I would ask myself

1.Which host installed the service?

2.Which user created the service?

3.What is the service name?

4.What binary or command does the service run?

5.Where is the service binary located?

6.Is the path normal for that service?

7.Was the service started after creation?

8.What account does the service run as?

9.Was sc.exe launched from an expected parent process?

10.Was the service created during an approved change window?

11.Does the same service exist on other hosts?

12.Did the same host show suspicious authentication activity?

13.Did the same host show PowerShell downloads?

14.Did the same host show Defender tampering?

15.Did the same host show LSASS access?

16.Was the Security log cleared after the service was created?

Severity
High

New service installation should be reviewed closely.
Services can run with elevated privileges and can be abused for persistence or execution.

Keep High if:
The service runs from Temp, Downloads, AppData, or another user-writable folder.
The service launches PowerShell or cmd.
The service name looks random or misleading.
The service was created by an unexpected user.
The service was created after suspicious logon activity.
The service was created after a PowerShell download.
The service was created after Defender tampering.
The service starts immediately after creation.
The same binary path appears on multiple hosts unexpectedly.

False Positives
Authorized administrator activity
Software installation
Endpoint management tools
Patch management agents
Backup agents
Monitoring agents
Security tool deployment
IT maintenance scripts
Lab validation

Tuning Notes
This search is broad on purpose for lab validation.
In production, I would tune based on the service name, binary path, signer, user, parent process, and whether the service is expected for that host.

Good tuning ideas:
Allowlist approved software and management agents.
Allowlist known security tools.
Alert higher on services running from user-writable folders.
Alert higher on services that launch PowerShell or cmd.
Alert higher when service creation follows suspicious logons.
Alert higher when service creation follows Defender tampering or LSASS access.
Correlate Event ID 7045 with Sysmon Event ID 1.
Correlate service creation with file creation and network activity.

Recommended Response to this alert:
Identify the affected host.
Identify the user who created the service.
Review the service name.
Review the service binary path.
Review the service start type.
Review the account the service runs as.
Check whether the service was started.
Check the parent process and command line.
Determine whether the service was authorized.
Search for the same service name across other hosts.
Search for the same binary path across other hosts.
Search for related PowerShell, downloads, LSASS access, Defender tampering, scheduled tasks, or event log clearing.
Stop and disable the service if it is unauthorized.
Delete the service if confirmed malicious.
Isolate the host if the service appears connected to active compromise.
Preserve logs and document the timeline.

Validation Evidence

1.Service creation command and service query confirmation
<img width="624" height="154" alt="12_service_creation_command" src="https://github.com/user-attachments/assets/57301e94-860e-4fad-919f-bcd91cdf5a9f" />

2.Windows System Event ID 7045 showing new service installation
<img width="624" height="175" alt="12_raw_7045_new_service_installed" src="https://github.com/user-attachments/assets/ceda9448-6a5f-4af5-b707-26f636faff8a" />

3.Sysmon Event ID 1 showing sc.exe process creation
<img width="624" height="230" alt="12_new_service_detection" src="https://github.com/user-attachments/assets/f791aa99-a3fa-4ce2-8a6e-125ebc0dff33" />

Analyst Conclusion
This detection confirmed new Windows service installation activity on Target-PC using Windows System Event ID 7045 and Sysmon Event ID 1.

The lab service was intentionally harmless and only wrote a simple text file. The value of this detection is that it confirms visibility into both the service installation event and the process that created it.

In a real SOC investigation, I would not stop at the fact that a service was installed. I would review the service name, binary path, start type, user context, parent process, and surrounding endpoint activity. New services become much more suspicious when they run from user-writable folders, launch scripting tools, start immediately, or appear after suspicious authentication, download, credential access, or defense evasion activity.
