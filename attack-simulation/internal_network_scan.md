# Detection 14: Internal Network Scan

## Objective

Detect internal network scanning activity from one host to another.

This detection identifies scan like network activity where one internal system attempts to connect to a target host across multiple ports. In this lab, Kali Linux performed a controlled Nmap scan against Target-PC. Windows Filtering Platform events were used to validate inbound connection attempts from the scanning host.

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Discovery | T1046 - Network Service Scanning | Kali scanned Target-PC across multiple TCP ports using Nmap. |

## Log Source

- Windows Security Logs
- Windows Filtering Platform
- Splunk Universal Forwarder
- Windows Event ID 5156: The Windows Filtering Platform has permitted a connection
- Host: Target-PC

## Detection Logic

This detection looks for Windows Filtering Platform events involving repeated inbound connections from the same source host to the same destination host.

In this lab, the key indicator was traffic from Kali Linux to Target-PC:

```text
Source IP: 192.168.10.250
Destination IP: 192.168.10.100
Direction: Inbound
Event ID: 5156
```

Internal scanning activity may indicate reconnaissance, service discovery, lateral movement preparation, or unauthorized network mapping.

## SPL Query

```spl
index=endpoint host="Target-PC" EventCode=5156 "192.168.10.250"
| table _time EventCode host ComputerName Direction SourceAddress SourcePort DestAddress DestPort Protocol Application
| sort -_time
```

If parsed fields are not available, the raw event can be reviewed with:

```spl
index=endpoint host="Target-PC" EventCode=5156 "192.168.10.250"
| table _time EventCode host ComputerName _raw
| sort -_time
```

## Safe Attack Simulation

A controlled Nmap scan was launched from Kali Linux against Target-PC.

Command used:

```bash
nmap -sS -Pn -p 1-1000 192.168.10.100
```

The scan targeted ports `1-1000` on Target-PC and identified TCP port `135` as open.

## Detection Result

Splunk returned Windows Filtering Platform events involving Kali’s IP address.

Observed evidence:

```text
Event ID: 5156
Message: The Windows Filtering Platform has permitted a connection
Source Address: 192.168.10.250
Destination Address: 192.168.10.100
Destination Port: 135
Direction: Inbound
Protocol: TCP
Host: Target-PC
```

The raw event matched the Nmap scan output, which showed port `135/tcp` open on Target-PC.

## Analyst Thought Process

### Initial Alert Meaning

A single internal host attempted network connections to another internal host. When this behavior occurs across many ports or systems, it may indicate network service scanning or reconnaissance.

### Key Questions

- Which host initiated the scan?
- Which host was targeted?
- Which ports were contacted?
- Was the scan authorized?
- Did the source host scan other systems?
- Did the scan occur before authentication attempts, service creation, or lateral movement?
- Was the source host a known administrator system, vulnerability scanner, or unknown endpoint?

### Evidence Reviewed

- Nmap output from Kali
- Windows Filtering Platform Event ID 5156
- Source IP address
- Destination IP address
- Destination port
- Direction of traffic
- Raw Windows Security event data

## Analyst Investigation Summary

A controlled Nmap scan was launched from Kali Linux against Target-PC. The scan targeted TCP ports `1-1000` and identified `135/tcp` as open. Splunk returned Windows Filtering Platform Event ID `5156` events involving Kali’s IP address `192.168.10.250`.

The raw event confirmed inbound traffic from Kali to Target-PC, including a connection to TCP port `135`. This matched the Nmap scan result and validated the internal network scan detection.

## Severity

Medium

Internal network scanning may be legitimate when performed by vulnerability scanners or administrators. It becomes more suspicious when the source host is not approved for scanning, the scan targets many hosts, occurs outside maintenance windows, or is followed by authentication attempts, service creation, remote execution, or lateral movement.

## False Positive Considerations

- Approved vulnerability scans
- Network discovery tools
- Administrator troubleshooting
- Asset inventory tools
- Endpoint management platforms
- Security team testing
- Lab-generated simulation activity

This detection becomes more suspicious when scanning is followed by brute-force attempts, successful logons, privileged group changes, scheduled task creation, or new service installation.

## Recommended Response

- Identify the source host.
- Identify the targeted host or subnet.
- Review scanned ports and protocols.
- Determine whether the source system is authorized to perform scanning.
- Check whether other systems were scanned by the same source.
- Review logs for follow-on activity such as failed logons, successful logons, service creation, or scheduled task creation.
- Validate whether the activity matches an approved vulnerability scan or maintenance window.
- Escalate if the scan source is unauthorized or associated with suspicious endpoint behavior.
- Document the timeline and affected systems.

## Validation Evidence

| Evidence | Screenshot |
|---|---|
| Kali Nmap scan against Target-PC | <img width="624" height="237" alt="14_nmap_scan_command" src="https://github.com/user-attachments/assets/355ae7c9-d72c-4b34-9bcf-a1e0937fbd33" /> |
| Raw Windows Filtering Platform Event ID 5156 showing inbound connection from Kali | <img width="624" height="348" alt="14_raw_firewall_scan_events" src="https://github.com/user-attachments/assets/f4791a75-10ac-4d83-b559-ee81f34eeb9e" /> |
| Splunk detection query showing firewall events involving Kali IP | <img width="624" height="163" alt="14_internal_network_scan_detection" src="https://github.com/user-attachments/assets/983efc69-a899-46e1-9550-1312769508f1" /> |

## Analyst Conclusion

In my conclusion, internal network scanning is an important behavior to investigate because it can represent legitimate vulnerability assessment activity or unauthorized reconnaissance. This lab showed how Nmap scan activity from Kali could be validated using Windows Filtering Platform Event ID 5156 on Target-PC. In a real investigation, I would review the source host, target host, scanned ports, timing, authorization status, and any follow-on activity to determine whether the scan was approved or suspicious.
