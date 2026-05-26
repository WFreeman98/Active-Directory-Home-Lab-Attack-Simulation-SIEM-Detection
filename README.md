Active Directory SIEM Detection Lab

Specifications
RAM: 16GB recommended
Disk: 120GB recommended
Hypervisor: VirtualBox
Domain: corp.local
SIEM: Splunk
Main index: endpoint
Lab only: yes

Systems
DC01: Windows Server 2022 Domain Controller
Target-PC: Windows 10 domain workstation
Kali: attack simulation box
Splunk: Ubuntu Server SIEM

Purpose
This lab was built to practice SOC analyst work in a small Active Directory environment.
The main goal was not just to run tools.
The goal was to generate attacker behavior, collect the logs, search the telemetry, validate detections, and write down what an analyst would check next.

All testing was done in an isolated lab.


Network Architecture

<img width="649" height="553" alt="Lab architecture" src="https://github.com/user-attachments/assets/6a08cc82-be36-40ef-8bd2-05fc6318c967" />


Lab Build

Stage 1 Virtual Machines
Built the main systems for the lab.
DC01 was used for Active Directory.
Target-PC was used as the workstation being attacked.
Kali was used to run controlled simulations.
Ubuntu Server was used to host Splunk.

<img width="662" height="591" alt="Virtual Machines" src="https://github.com/user-attachments/assets/116d14a8-486e-4d61-86c0-4e2d72598e4d" />

<img width="546" height="629" alt="Virtual Machine Kali" src="https://github.com/user-attachments/assets/242e9add-7d70-4aa0-9775-120f55323654" />

<img width="544" height="592" alt="VM Windows 2022" src="https://github.com/user-attachments/assets/c887fe1f-8e01-4765-9017-8e6f3078ea5e" />

<img width="662" height="589" alt="VM SIEM" src="https://github.com/user-attachments/assets/fa09d407-d5c0-40db-84a6-a45b45b9f310" />


Stage 2 Network Configuration
Configured the lab network so the Windows systems, Kali, and Splunk could communicate.
Verified connectivity before installing logging tools.

Checks used:
ping DC01
ping Target-PC
ping Splunk
nslookup corp.local
ipconfig /all

<img width="662" height="178" alt="Network Connectivity" src="https://github.com/user-attachments/assets/2aa40b2f-0112-4d3f-a552-1867306c0d5d" />

<img width="647" height="172" alt="SIEM Static IP" src="https://github.com/user-attachments/assets/441bf0cf-84d6-4041-a72d-c77681333a74" />


Stage 3 Active Directory Setup
Built the corp.local domain.
Created test users and groups for the detection tests.
Kept the lab simple so the logs were easier to understand.

<img width="662" height="507" alt="Active Directory Setup" src="https://github.com/user-attachments/assets/e21dc146-2ae1-48aa-8969-4939a98463ee" />


Stage 4 Domain Join
Joined Target-PC to corp.local.
Confirmed the workstation could authenticate against the domain.

<img width="411" height="402" alt="Domain J" src="https://github.com/user-attachments/assets/fce8fdf9-569b-46da-8ff6-c4b988380bab" />

<img width="662" height="464" alt="Domain Join" src="https://github.com/user-attachments/assets/a8ae7cf7-9210-45bf-af64-6e0f0a3026b2" />


Stage 5 Sysmon and Splunk Log Ingestion
Installed Sysmon on Windows.
Installed the Splunk Universal Forwarder.
Forwarded Windows Security logs and Sysmon logs into Splunk.

Main logs used:
Windows Security
Microsoft-Windows-Sysmon/Operational
Windows System
Windows PowerShell / PowerShell Operational when available

Main Splunk index:
endpoint

Basic validation search:
index=endpoint
| stats count by host sourcetype source
| sort -count

<img width="581" height="190" alt="Sysmon Running" src="https://github.com/user-attachments/assets/e9986a1d-80a1-4589-9391-03fe39439f85" />

<img width="597" height="550" alt="Sysmon Event Viewer" src="https://github.com/user-attachments/assets/615edd37-0850-4edd-b590-84dc1c5a978a" />

<img width="662" height="469" alt="Splunk Log Ingestion" src="https://github.com/user-attachments/assets/2500f254-2cf7-4e99-9160-f3c007708576" />


Logging Checks

Windows Security check:
index=endpoint source="*WinEventLog:Security*"
| stats count by host EventCode
| sort -count

Sysmon check:
index=endpoint source="*Sysmon*"
| stats count by host EventCode EventID
| sort -count

Recent endpoint activity:
index=endpoint host="Target-PC"
| table _time host source sourcetype EventCode EventID Account_Name Image CommandLine
| sort -_time


Detection Validation Process

For each detection I used the same workflow.

1. Run the simulation in the lab
2. Confirm the Windows or Sysmon event exists
3. Search the raw event in Splunk
4. Identify the important fields
5. Build a basic SPL search
6. Check false positives
7. Write analyst notes
8. Save screenshots as proof

I kept the first searches broad on purpose.
The point was to prove the telemetry first.
After that the detections can be tuned.


Detection Rule Index

1 RDP Brute Force
MITRE: T1110, T1021.001
Status: Validated
Evidence file: attack-simulation/hydra_rdp_bruteforce.md

2 Successful Login After Failures
MITRE: T1110, T1078, T1021.001
Status: Validated
Evidence file: attack-simulation/successful_login_after_failures.md

3 Password Spraying
MITRE: T1110.003, T1021.001
Status: Validated
Evidence file: attack-simulation/password_spraying.md

4 New Account Created
MITRE: T1136.002
Status: Validated
Evidence file: attack-simulation/new_account_created.md

5 Privileged Group Change
MITRE: T1098
Status: Validated
Evidence file: attack-simulation/privileged_group_change.md

6 Encoded PowerShell
MITRE: T1059.001, T1027
Status: Validated
Evidence file: attack-simulation/encoded_powershell.md

7 PowerShell Download Cradle
MITRE: T1105, T1059.001
Status: Validated
Evidence file: attack-simulation/powershell_download_cradle.md

8 LSASS Access
MITRE: T1003.001
Status: Validated
Evidence file: attack-simulation/lsass_access.md

9 Event Log Clearing
MITRE: T1070.001
Status: Validated
Evidence file: attack-simulation/event_log_clearing.md

10 Defender Tampering
MITRE: T1562.001
Status: Validated
Evidence file: attack-simulation/defender_tampering.md

11 Scheduled Task Created
MITRE: T1053.005
Status: Validated
Evidence file: attack-simulation/scheduled_task_created.md

12 New Service Installed
MITRE: T1543.003
Status: Validated
Evidence file: attack-simulation/new_service_installed.md

13 Certutil File Download
MITRE: T1105, T1218
Status: Validated
Evidence file: attack-simulation/certutil_file_download.md

14 Internal Network Scan
MITRE: T1046
Status: Validated
Evidence file: attack-simulation/internal_network_scan.md

15 Successful Login Then Persistence
MITRE: T1078, T1136.001, T1098
Status: Validated
Evidence file: attack-simulation/successful_login_then_persistence.md

Validation tracker:
validation/detection_validation_matrix.md


Detection 01 RDP Brute Force

Goal
Detect repeated failed RDP logons against Target-PC.

Simulation
Kali was used to generate failed RDP authentication attempts against the Windows workstation.

Expected logs
Windows Security 4625
Possible logon type 10 for RDP
Possible logon type 3 depending on NLA behavior

Splunk search
index=endpoint host="Target-PC" EventCode=4625
| stats count min(_time) as first_seen max(_time) as last_seen by src_ip Account_Name host Logon_Type
| convert ctime(first_seen) ctime(last_seen)
| sort -count

Analyst checks
Check the source IP.
Check the targeted account.
Check the logon type.
Check the time window.
Check if a successful logon happened after the failures.

Screenshot evidence

<img width="649" height="512" alt="Hydra Attack" src="https://github.com/user-attachments/assets/78124f35-ffdc-4a65-98d3-7c881a27278d" />


Detection 02 Successful Login After Failures

Goal
Find a successful login that happens after repeated failed logons.

Expected logs
4625 failed logon
4624 successful logon

Splunk search
index=endpoint host="Target-PC" (EventCode=4625 OR EventCode=4624)
| table _time host EventCode Account_Name src_ip Logon_Type
| sort _time

Better review search
index=endpoint host="Target-PC" (EventCode=4625 OR EventCode=4624)
| stats values(EventCode) as event_codes count min(_time) as first_seen max(_time) as last_seen by Account_Name src_ip host
| convert ctime(first_seen) ctime(last_seen)
| where mvfind(event_codes,"4624")>=0 AND mvfind(event_codes,"4625")>=0
| sort -count

Analyst checks
Was the login expected.
Was it the same account that failed earlier.
Was the source IP the same.
Was the source system normal for that user.
Was there follow-on activity after the login.


Detection 3 Password Spraying

Goal
Detect one source trying a password against multiple accounts.

Expected logs
Windows Security 4625

Splunk search
index=endpoint EventCode=4625
| stats count dc(Account_Name) as unique_accounts values(Account_Name) as accounts by src_ip host
| where unique_accounts >= 3
| sort -unique_accounts

Analyst checks
One source IP hitting multiple users is more important than one user failing many times.
Check the time window.
Check for service accounts.
Check for lockouts.
Check if any account later logged in successfully.


Detection 04 New Account Created

Goal
Detect new Active Directory account creation.

Expected log
Windows Security 4720

Splunk search
index=endpoint EventCode=4720
| table _time host Subject_Account_Name Target_Account_Name EventCode
| sort -_time

Analyst checks
Who created the account.
What account was created.
Was the account expected.
Was the account used shortly after creation.
Was it added to a privileged group.

Screenshot evidence

<img width="662" height="523" alt="Atomic Execution" src="https://github.com/user-attachments/assets/a1e503e6-335c-4fa1-a4c6-c9cadd363f5f" />

<img width="662" height="467" alt="Account Creation Detection" src="https://github.com/user-attachments/assets/a3ae763d-2fbe-4496-9156-53ffd1e334a6" />


Detection 5 Privileged Group Change

Goal
Detect when a user is added to an administrator or privileged group.

Expected logs
4728 global security group member added
4732 local security group member added

Splunk search
index=endpoint (EventCode=4728 OR EventCode=4732)
| table _time host EventCode Subject_Account_Name Target_Account_Name Group_Name
| sort -_time

Analyst checks
Who made the change.
What group was changed.
What user was added.
Was the change tied to a ticket.
Did the new privileged user log in after the change.


Detection 6 Encoded PowerShell

Goal
Detect PowerShell running with encoded command arguments.

Expected log
Sysmon Event ID 1

Splunk search
index=endpoint source="*Sysmon*"
("powershell.exe" AND ("-enc" OR "-encodedcommand" OR "EncodedCommand"))
| table _time host Image ParentImage CommandLine User EventCode EventID
| sort -_time

Analyst checks
Look at the full command line.
Decode the command when safe.
Check the parent process.
Check the user context.
Check if the host made network connections after execution.


Detection 7 PowerShell Download Cradle

Goal
Detect PowerShell being used to download content from a remote host.

Simulation
Kali hosted a harmless file.
Target-PC downloaded the file using PowerShell.

Expected logs
Sysmon Event ID 1 process creation
Sysmon Event ID 3 network connection if enabled

Splunk search
index=endpoint source="*Sysmon*"
("powershell.exe" AND ("Invoke-WebRequest" OR "DownloadString" OR "DownloadFile" OR "http://" OR "https://"))
| table _time host Image ParentImage CommandLine DestinationIp DestinationPort EventCode EventID
| sort -_time

Analyst checks
Review the URL.
Review the destination IP.
Review the downloaded file name.
Review the parent process.
Check whether the destination is internal or external.


Detection 8 LSASS Access

Goal
Detect suspicious access to lsass.exe.

Expected log
Sysmon Event ID 10

Splunk search
index=endpoint source="*Sysmon*" EventCode=10
("lsass.exe")
| table _time host SourceImage TargetImage GrantedAccess CallTrace User EventCode EventID
| sort -_time

Analyst checks
Check the source process.
Check GrantedAccess.
Check whether the process is expected security software.
Check if the account is admin.
Check for follow-on logons or lateral movement.

Tuning notes
Security tools can touch LSASS.
Do not alert only because lsass.exe appears.
The source process and access rights matter.


Detection 9 Event Log Clearing

Goal
Detect clearing of Windows event logs.

Expected log
Windows Security 1102

Splunk search
index=endpoint EventCode=1102
| table _time host Account_Name Subject_Account_Name EventCode
| sort -_time

Analyst checks
Who cleared the log.
Which host generated the event.
What happened before the clear.
Was the action approved maintenance.
Were centralized logs preserved in Splunk.


Detection 10 Defender Tampering

Goal
Detect suspicious Defender configuration changes.

Expected indicators
Set-MpPreference
DisableRealtimeMonitoring
Defender exclusions
PowerShell touching Defender settings

Splunk search
index=endpoint
("Set-MpPreference" OR "DisableRealtimeMonitoring" OR "Add-MpPreference" OR "ExclusionPath")
| table _time host Image ParentImage CommandLine User EventCode EventID
| sort -_time

Analyst checks
Check who ran the command.
Check whether the command disabled protections or added exclusions.
Check if this came from an admin process or suspicious parent process.
Check whether malware alerts or suspicious process execution happened before this.


Detection 11 Scheduled Task Created

Goal
Detect scheduled task creation that could be used for persistence.

Expected log
Windows Security 4698

Splunk search
index=endpoint EventCode=4698
| table _time host Account_Name Task_Name TaskContent EventCode
| sort -_time

Analyst checks
Task name.
Task action.
User that created it.
Schedule trigger.
Whether the path points to a suspicious location.


Detection 12 New Service Installed

Goal
Detect a new Windows service being installed.

Expected log
Windows System 7045

Splunk search
index=endpoint EventCode=7045
| table _time host Service_Name Service_File_Name Account_Name EventCode
| sort -_time

Analyst checks
Service name.
Binary path.
Install account.
Whether the path is in Temp, Users, ProgramData, or another suspicious location.
Whether the service started after being installed.


Detection 13 Certutil File Download

Goal
Detect certutil.exe being used to download a file.

Simulation
Kali hosted a harmless text file.
Target-PC used certutil.exe to download it.

Kali
mkdir -p /home/kali/certutil-test
cd /home/kali/certutil-test
echo "certutil test file" > update.txt
python3 -m http.server 8000

Target-PC
certutil.exe -urlcache -f http://192.168.10.250:8000/update.txt update.txt

Expected log
Sysmon Event ID 1

Splunk search
index=endpoint host="Target-PC" source="*Sysmon*"
("certutil.exe" OR "urlcache" OR "http://" OR "https://")
| table _time host Image ParentImage CommandLine User EventCode EventID
| sort -_time

Analyst checks
certutil.exe path.
-urlcache usage.
Remote URL.
Parent process.
User context.
File name written to disk.

Note
This did not download malware.
The file was only used to validate the detection.


Detection 14 Internal Network Scan

Goal
Detect internal scanning behavior from the Kali host or another system.

Expected evidence
Network traffic from one source to many destinations or ports.
Sysmon network events if endpoint network logging is enabled.

Example validation idea
nmap scan from Kali against the lab subnet.

Splunk search
index=endpoint source="*Sysmon*" EventCode=3
| stats dc(DestinationIp) as unique_destinations dc(DestinationPort) as unique_ports count by host Image SourceIp
| sort -unique_ports

Analyst checks
Source host.
Destination range.
Number of ports.
Number of hosts.
Whether the source system normally scans the network.


Detection 15 Successful Login Then Persistence

Goal
Correlate a successful logon with account or privilege changes after the login.

Expected logs
4624 successful logon
4720 new account
4728 privileged group change
4732 local group change

Splunk search
index=endpoint (EventCode=4624 OR EventCode=4720 OR EventCode=4728 OR EventCode=4732)
| table _time host EventCode Account_Name Subject_Account_Name Target_Account_Name Group_Name src_ip Logon_Type
| sort _time

Analyst checks
Did the same user log in and then make changes.
Did the login come from an unusual source.
Was a new account created after login.
Was a privileged group modified.
Was this normal admin work or possible persistence.


Example Splunk Evidence

<img width="1000" height="635" alt="Splunk Detection" src="https://github.com/user-attachments/assets/eab62698-2eba-46ba-bc8e-fdad82a70455" />


Investigation Notes

Authentication alerts
Check source IP.
Check target account.
Check logon type.
Check failure count.
Check if a success happened after failures.
Check whether the account is privileged.

Account and privilege alerts
Check who made the change.
Check whether there was a ticket or approved admin work.
Check whether the account was used after creation.
Check if the account was added to a privileged group.

PowerShell and process alerts
Check Image.
Check ParentImage.
Check CommandLine.
Check user context.
Check network connections after execution.
Check file writes after execution.

Credential access alerts
Check source process.
Check target process.
Check access rights.
Check whether the source process is normal security software.
Check for follow-on authentication activity.


False Positives

Expected false positives
Help desk activity
Admin scripts
Patch management
Security tools
Software installs
Approved scheduled tasks
Approved services
Internal scanning tools
PowerShell administration

Tuning ideas
Allowlist known admin servers.
Allowlist known service accounts.
Allowlist known patching tools.
Add time windows.
Alert on unusual source hosts.
Correlate process activity with authentication activity.
Correlate new accounts with group changes.
Review parent process before escalating.


Response Notes

If an alert looked real, I would check:
Affected host
Affected user
Source IP
Timeline before and after the alert
Successful logons after failures
New accounts
Group changes
Suspicious PowerShell
Suspicious service or scheduled task creation
Potential credential access
Whether the host needs isolation
Whether passwords need reset
Whether logs need preserved


What I Learned

Telemetry validation matters first.
A tool can fail but the logs can still be useful.
Raw events matter because fields are not always clean.
Broad SPL is useful during lab validation.
Production detections need more tuning.
Screenshots are important because they prove the activity happened.
The strongest evidence is the attack step, raw event, and final Splunk result together.


Limitations

This is a home lab.
It is not a production enterprise network.
Some searches use lab hostnames and lab IP addresses.
Some detections are intentionally broad.
The point was to validate telemetry and analyst workflow first.

Future improvements
Convert detections to Sigma.
Add correlation searches.
Add dashboards.
Add SOAR case workflow.
Add alert severity notes.
Add timeline screenshots for each detection.
Add network evidence with Wireshark or Zeek.


Repository Structure

Active-Directory-SIEM-Detection-Lab/

README.md

attack-simulation/
hydra_rdp_bruteforce.md
successful_login_after_failures.md
password_spraying.md
new_account_created.md
privileged_group_change.md
encoded_powershell.md
powershell_download_cradle.md
lsass_access.md
event_log_clearing.md
defender_tampering.md
scheduled_task_created.md
new_service_installed.md
certutil_file_download.md
internal_network_scan.md
successful_login_then_persistence.md

validation/
detection_validation_matrix.md

images/
project screenshots
