Detection 14 Internal Network Scan

Objective
Detect internal network scanning activity from one host to another.

This detection uses Windows Filtering Platform events from Target-PC.
The main event used for this detection is Windows Security Event ID 5156.

The goal is to identify when one internal host attempts connections to another internal host across ports.
In this lab, Kali Linux scanned Target-PC using Nmap.

Internal scanning can be normal when it comes from vulnerability scanners or admin systems.
It still needs to be reviewed because scanning can also be reconnaissance before brute force, lateral movement, service abuse, or exploitation.

Lab Setup
Scanner: Kali Linux
Target: Target-PC
SIEM: Splunk
Log Source: Windows Security
Telemetry: Windows Filtering Platform
Event ID: 5156
Source IP: 192.168.10.250
Destination IP: 192.168.10.100
Target Port Seen: 135

MITRE ATT&CK
Discovery: T1046 - Network Service Scanning

Detection Logic
Look for repeated Windows Filtering Platform events involving one source host connecting to a target host.

In this lab, the key behavior was traffic from Kali to Target-PC.

Important indicators:
EventCode 5156
SourceAddress 192.168.10.250
DestAddress 192.168.10.100
Direction Inbound
Multiple destination ports
Nmap scan output
Target-PC firewall events

SPL Search
index=endpoint host="Target-PC" EventCode=5156 "192.168.10.250"
| table _time EventCode host ComputerName Direction SourceAddress SourcePort DestAddress DestPort Protocol Application
| sort -_time

Raw Event Search
index=endpoint host="Target-PC" EventCode=5156 "192.168.10.250"
| table _time EventCode host ComputerName _raw
| sort -_time

Port Count Search
index=endpoint host="Target-PC" EventCode=5156 "192.168.10.250"
| stats count dc(DestPort) as unique_ports values(DestPort) as scanned_ports by SourceAddress DestAddress host
| sort -unique_ports

Safe Lab Simulation
A controlled Nmap scan was launched from Kali Linux against Target-PC.

Command used:
nmap -sS -Pn -p 1-1000 192.168.10.100

The scan targeted TCP ports 1 through 1000 on Target-PC.
Nmap identified TCP port 135 as open.

This test was controlled.
It was performed inside the lab.
It did not exploit the target.
It did not brute-force credentials.
It did not modify the system.
It was only used to generate network scan telemetry.

Detection Result
Splunk returned Windows Filtering Platform Event ID 5156 events from Target-PC.

Observed evidence:
Event ID: 5156
Message: The Windows Filtering Platform has permitted a connection
Source Address: 192.168.10.250
Destination Address: 192.168.10.100
Destination Port: 135
Direction: Inbound
Protocol: TCP
Host: Target-PC

The Splunk evidence matched the Nmap result.
Nmap showed 135/tcp open, and the Windows event showed inbound traffic from Kali to Target-PC on port 135.

Analyst Review
The first thing I checked was whether the scan source matched the Kali machine.
The Windows Filtering Platform event showed SourceAddress 192.168.10.250, which matched Kali.

The next thing I checked was whether the destination matched Target-PC.
The event showed traffic to 192.168.10.100, which matched Target-PC.

The important part is the pattern.
One connection to one port may not be enough by itself.
Repeated connections from the same source to multiple ports or multiple hosts is what makes this look like scanning.

The important fields were:
SourceAddress
SourcePort
DestAddress
DestPort
Direction
Protocol
Application
Host
ComputerName
EventCode
_time

Investigation Questions I would ask myself

1.Which host initiated the scan?

2.Which host was targeted?

3.How many ports were contacted?

4.Which ports were open?

5.Was the source host authorized to scan?

6.Was the source host a vulnerability scanner?

7.Did the scan happen during an approved maintenance window?

8.Did the same source scan other hosts?

9.Did the scan happen before failed logons?

10.Did the scan happen before a successful logon?

11.Did the scan happen before service creation?

12.Did the scan happen before scheduled task creation?

13.Did the scan happen before lateral movement?

14.Is the source host expected to communicate with the target?

Severity
Medium

Raise to High if:
The source host is not approved for scanning.
The scan targets many hosts.
The scan targets sensitive systems.
The scan occurs outside maintenance windows.
The scan is followed by failed logons.
The scan is followed by a successful logon.
The scan is followed by new service creation.
The scan is followed by scheduled task creation.
The scan is followed by PowerShell execution or file downloads.

False Positives
Approved vulnerability scans
Network discovery tools
Administrator troubleshooting
Asset inventory tools
Endpoint management platforms
Security team testing
Lab validation

Tuning Notes
This search is broad on purpose for lab validation.
In production, I would tune by approved scanner IPs, target subnet, maintenance windows, port count, host count, and follow-on activity.

Good tuning ideas:
Allowlist approved vulnerability scanners.
Track scans outside maintenance windows.
Alert higher when one source touches many ports.
Alert higher when one source touches many hosts.
Alert higher when scanning is followed by authentication attempts.
Alert higher when scanning is followed by service creation or scheduled tasks.
Correlate scan activity with Windows Security Event ID 4625 and 4624.
Correlate scan activity with Sysmon process and network events.

Recommended Response for this alert:
Identify the source host.
Identify the target host or subnet.
Review the scanned ports.
Determine whether the source is an approved scanner.
Check if the scan occurred during an approved window.
Search for other hosts scanned by the same source.
Review authentication activity after the scan.
Review service creation and scheduled task activity after the scan.
Review endpoint activity from the source host if available.
Escalate if the source is unauthorized or tied to suspicious behavior.
Document the source, target, ports, timing, and follow-on activity.

Validation Evidence

1.Kali Nmap scan against Target-PC
<img width="624" height="237" alt="14_nmap_scan_command" src="https://github.com/user-attachments/assets/355ae7c9-d72c-4b34-9bcf-a1e0937fbd33" />

2.Raw Windows Filtering Platform Event ID 5156 showing inbound connection from Kali
<img width="624" height="348" alt="14_raw_firewall_scan_events" src="https://github.com/user-attachments/assets/f4791a75-10ac-4d83-b559-ee81f34eeb9e" />

3.Splunk detection query showing firewall events involving Kali IP
<img width="624" height="163" alt="14_internal_network_scan_detection" src="https://github.com/user-attachments/assets/983efc69-a899-46e1-9550-1312769508f1" />

Analyst Conclusion
This detection confirmed internal network scanning activity from Kali to Target-PC using Windows Filtering Platform Event ID 5156.

The scan was safely performed with Nmap in the lab and targeted TCP ports 1 through 1000. Splunk showed inbound connection events from 192.168.10.250 to 192.168.10.100, and the firewall event matched the Nmap output showing port 135 open.

In a real SOC investigation, I would not treat every scan as malicious right away. I would first confirm whether the source host is an approved vulnerability scanner or admin system. If the source is not approved, I would review the scanned ports, scope the activity across other hosts, and check for follow-on behavior such as failed logons, successful logons, scheduled tasks, new services, PowerShell activity, or lateral movement.
