Detection 11 Scheduled Task Created

Objective
Detect scheduled task creation activity on a Windows endpoint.

This detection uses Windows Security Event ID 4698 and Sysmon Event ID 1 from Target-PC.
The goal is to identify when a scheduled task is created and review what the task is configured to run.

Scheduled tasks are normal in Windows environments.
They still need to be reviewed because attackers often use them for persistence, execution, and recurring command activity.

Lab Setup
Host: Target-PC
SIEM: Splunk
Log Sources: Windows Security and Sysmon
Windows Event ID: 4698
Sysmon Event ID: 1
Tool Used: schtasks.exe
Task Name: \Maintenance\Endpoint-Health-Check

MITRE ATT&CK
Persistence: T1053.005 - Scheduled Task
Execution: T1053.005 - Scheduled Task

Detection Logic
Look for scheduled task creation using both Windows Security logs and Sysmon process creation logs.

Windows Security Event ID 4698 confirms that a scheduled task was created.
Sysmon Event ID 1 confirms the process activity that created the task.

Important indicators:
schtasks.exe
/create
TaskName
TaskContent
CommandLine
ParentImage
User
EventCode 4698
EventCode 1

SPL Search
index=endpoint host="Target-PC" ("Endpoint-Health-Check" OR "schtasks")
| table _time EventCode EventID host ComputerName source Image CommandLine TaskName Message _raw
| sort -_time

Windows Security Search
index=endpoint host="Target-PC" EventCode=4698
| table _time EventCode host ComputerName Account_Name TaskName Message _raw
| sort -_time

Sysmon Process Search
index=endpoint host="Target-PC" source="*Sysmon*" EventCode=1 "schtasks"
| table _time EventCode EventID host ComputerName Image CommandLine ParentImage User
| sort -_time

Safe Lab Simulation
A harmless scheduled task was created on Target-PC using schtasks.exe.

Command used:
schtasks /create /tn "\Maintenance\Endpoint-Health-Check" /tr "cmd.exe /c echo Endpoint health check completed > C:\Windows\Temp\endpoint_health_check.txt" /sc once /st 23:59 /f

Task name:
\Maintenance\Endpoint-Health-Check

Cleanup command:
schtasks /delete /tn "\Maintenance\Endpoint-Health-Check" /f

This test was safe.
It did not execute malware.
It did not download payloads.
It did not modify Defender.
It did not create persistence for a malicious tool.
It only created a benign scheduled task for detection validation.

Detection Result
Splunk returned scheduled task creation evidence from Target-PC.

Windows Security showed:
Event ID: 4698
Message: A scheduled task was created
Task Name: \Maintenance\Endpoint-Health-Check
Host: Target-PC
User: Administrator

Sysmon showed:
Event ID: 1
Image: C:\Windows\System32\schtasks.exe
CommandLine: schtasks /create ...

Analyst Review
The first thing I checked was whether the task creation was visible in Windows Security logs.
Event ID 4698 confirmed that a scheduled task was created.

The next thing I checked was the process that created it.
Sysmon Event ID 1 showed schtasks.exe process creation and captured the command line.

The important part is the task action.
A task name by itself does not prove malicious activity.
The command the task runs matters more.

In this lab, the task action was benign and only wrote a text file to C:\Windows\Temp.
In a real SOC investigation, I would check whether the task runs PowerShell, cmd, rundll32, regsvr32, a script, an executable from a user folder, or anything from Temp, Downloads, or AppData.

Important fields:
Host
User
TaskName
TaskContent
Image
CommandLine
ParentImage
EventCode
EventID
_time

Investigation Questions I would ask myself

1.Which host created the scheduled task?

2.Which user created the task?

3.What is the task name?

4.What command does the task run?

5.Where does the task action point?

6.Is the task set to run once or repeatedly?

7.Is it triggered at logon or startup?

8.Does it run with elevated privileges?

9.Was the task created during a normal change window?

10.Was the task created after suspicious authentication activity?

11.Did the same host show PowerShell downloads?

12.Did the same host show Defender tampering?

13.Did the same host show LSASS access?

14.Was the Security log cleared after the task was created?

Severity
Medium

Raise to High if:
The task runs PowerShell.
The task runs an executable from Temp, Downloads, or AppData.
The task runs from an unusual path.
The task was created by an unexpected user.
The task is configured to run at logon or startup.
The task runs with elevated privileges.
The task appears after suspicious logon activity.
The task appears after a PowerShell download.
The task appears after Defender tampering.
The task appears before or after event log clearing.

False Positives
Administrator automation
Software deployment tools
Endpoint management platforms
Patch management tasks
Backup agents
Monitoring agents
IT maintenance scripts
Lab validation

Tuning Notes
This search is broad on purpose for lab validation.
In production, I would tune based on the task action, user, parent process, path, trigger, and whether the task is expected for that host.

Good tuning ideas:
Allowlist approved software deployment tasks.
Allowlist known endpoint management tasks.
Alert higher on tasks that run PowerShell or cmd.
Alert higher on tasks that execute from user-writable folders.
Alert higher when tasks are created after suspicious logons.
Alert higher when the task name looks random or misleading.
Correlate Event ID 4698 with Sysmon Event ID 1.
Correlate scheduled task creation with file creation and network events.

Recommended Response for this alert:
Identify the affected host.
Identify the user who created the task.
Review the task name.
Review the task action.
Review the task trigger.
Review whether it runs with elevated privileges.
Check the parent process and command line.
Determine whether the task was authorized.
Search for similar tasks across other hosts.
Search for related PowerShell, downloads, LSASS access, Defender tampering, or event log clearing.
Disable or delete the task if it is unauthorized.
Isolate the host if the task appears connected to active compromise.
Document the full timeline.

Validation Evidence

1.Scheduled task creation command and query confirmation
<img width="624" height="158" alt="11_schtasks_creation_command" src="https://github.com/user-attachments/assets/726dd9e0-f1ea-4054-9186-5b385863252e" />

2.Windows Security Event ID 4698 showing scheduled task creation
<img width="624" height="387" alt="11_raw_4698_scheduled_task_created" src="https://github.com/user-attachments/assets/79835ffb-d701-40ac-a69e-75ee0a359702" />

3.Sysmon Event ID 1 showing schtasks.exe process creation
<img width="624" height="238" alt="11_scheduled_task_detection" src="https://github.com/user-attachments/assets/1228d70b-fc5d-49f2-afbe-bfacebbbece8" />

Analyst Conclusion
This detection confirmed scheduled task creation activity on Target-PC using Windows Security Event ID 4698 and Sysmon Event ID 1.

The lab task was intentionally harmless and only wrote a simple text file. The value of the detection is that it confirms visibility into both the scheduled task event and the process that created it.

In a real SOC investigation, I would not stop at the fact that a task was created. I would review the task action, trigger, user context, parent process, and surrounding endpoint activity. Scheduled tasks become much more suspicious when they run PowerShell, execute from user-writable folders, run at logon or startup, or appear after suspicious authentication, download, credential access, or defense evasion activity.
