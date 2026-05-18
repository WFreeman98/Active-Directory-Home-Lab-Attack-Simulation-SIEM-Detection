# Detection 07: PowerShell Download Cradle

## Objective

Detect PowerShell activity used to download a file from a remote web server.

This detection identifies PowerShell network activity where a Windows endpoint connects to an external or suspicious host to download content. In this lab, Target-PC used PowerShell `Invoke-WebRequest` to download a harmless text file from a Kali-hosted web server. Sysmon captured the network connection as Event ID `3`.

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Command and Control | T1105 - Ingress Tool Transfer | Target-PC connected to the Kali web server and downloaded a file. |
| Execution | T1059.001 - Command and Scripting Interpreter: PowerShell | PowerShell was used to initiate the download activity. |

## Log Source

- Sysmon Operational Logs
- Splunk Universal Forwarder
- Sysmon Event ID 3
- Host: Target-PC

## Detection Logic

This detection looks for PowerShell-related download behavior and network connections from Target-PC to the Kali attacker machine.

A PowerShell download cradle is commonly used by attackers to retrieve payloads, scripts, or tools from a remote server. In this lab, the downloaded file was a harmless text file used only to safely generate telemetry.

## SPL Query

```spl
index=endpoint host="Target-PC" "192.168.10.250" "8000"
| table _time source EventCode EventID _raw
| sort -_time
```

## Attack Simulation

A harmless text file was created and hosted on Kali using Python’s built-in HTTP server.

Kali commands:

```bash
mkdir -p /home/kali/soc-web
cd /home/kali/soc-web
echo "SOC Lab PowerShell Download Cradle Test" > test.txt
python3 -m http.server 8000
```

Target-PC PowerShell command:

```powershell
Invoke-WebRequest -Uri "http://192.168.10.250:8000/test.txt" -OutFile "$env:TEMP\soc_lab_test.txt"
```

The file contents were verified with:

```powershell
Get-Content "$env:TEMP\soc_lab_test.txt"
```

Expected output:

```text
SOC Lab PowerShell Download Cradle Test
```

This test did not execute malware, download tools, create persistence, or modify security settings. It was used only to generate safe Sysmon telemetry.

## Detection Result

Splunk detected a Sysmon Event ID `3` network connection from Target-PC to the Kali web server.

The event showed:

```text
Host: Target-PC
Source: Microsoft-Windows-Sysmon/Operational
Event ID: 3
Destination IP: 192.168.10.250
Destination Port: 8000
Process: powershell.exe
```

## Analyst Thought Process

### Initial Alert Meaning

PowerShell made a network connection to a remote web server. This may indicate a download cradle, script retrieval, or possible payload staging activity.

### Key Questions

- Which host initiated the network connection?
- Which user executed PowerShell?
- What destination IP and port were contacted?
- Was the destination expected or suspicious?
- What file or content was downloaded?
- Did PowerShell execute anything after the download?
- Were there related process creation, file creation, or network events?

### Evidence Reviewed

- Sysmon Event ID 3
- Host: Target-PC
- Destination IP: 192.168.10.250
- Destination port: 8000
- Kali Python web server
- PowerShell download command
- Downloaded file: `soc_lab_test.txt`

## Analyst Investigation Summary

I began by hosting a harmless text file on Kali using Python’s built-in HTTP server. I then used PowerShell `Invoke-WebRequest` from Target-PC to download the file from the Kali web server.

After the download completed, I searched Splunk for Sysmon telemetry showing network activity from Target-PC to Kali. Splunk returned a Sysmon Event ID `3` event showing a connection from Target-PC to `192.168.10.250` on port `8000`.

This confirmed that Sysmon captured the network connection associated with the PowerShell download behavior. In a real SOC investigation, this activity would require review of the downloaded content, parent process, user context, and any follow-on execution.

## Severity

Medium

Increase to High if the downloaded content is suspicious, executed after download, written to a sensitive location, or followed by persistence, credential access, or defense evasion activity.

## False Positive Considerations

- Administrator scripts
- Software deployment tools
- Internal automation
- Security testing
- Lab-generated validation activity
- Legitimate PowerShell-based downloads from trusted sources

This detection becomes more suspicious when PowerShell connects to an unusual IP address, uses uncommon ports, downloads executable content, or is launched by an unusual parent process.

## Recommended Response

- Identify the host and user involved.
- Review the destination IP and determine whether it is trusted.
- Inspect the downloaded file.
- Check whether the file was executed after download.
- Review related Sysmon Event ID 1 process creation events.
- Review related Sysmon Event ID 11 file creation events if available.
- Search for additional PowerShell activity from the same host.
- Isolate the host if malicious behavior is confirmed.
- Document the full timeline of download and follow-on activity.

## Validation Evidence

| Evidence | Screenshot |
|---|---|
| Kali web server hosting the test file | <img width="624" height="280" alt="07_kali_web_server_hosting_file" src="https://github.com/user-attachments/assets/9ce24c53-9579-42a1-989d-75c9d3c767d2" /> |
| Raw Sysmon Event ID 3 network connection evidence | <img width="624" height="276" alt="07_raw_sysmon_powershell_download_events" src="https://github.com/user-attachments/assets/6340c5d5-b11a-4bd7-a4c5-3c030e805ecb" /> |
| Splunk detection showing Target-PC connection to Kali web server | <img width="624" height="277" alt="07_powershell_download_cradle_detection" src="https://github.com/user-attachments/assets/82ce02a7-3e6f-4f54-8100-787fc1708767" /> |

## Analyst Conclusion

This detection successfully identified PowerShell download cradle behavior from Target-PC to the Kali attacker machine. The activity was safely simulated using a harmless text file hosted on Kali and downloaded through PowerShell.

Splunk detected the activity through Sysmon Event ID `3`, showing Target-PC connecting to `192.168.10.250` on port `8000`. In a real SOC investigation, this behavior would be reviewed for possible payload download, script staging, or command-and-control activity.
