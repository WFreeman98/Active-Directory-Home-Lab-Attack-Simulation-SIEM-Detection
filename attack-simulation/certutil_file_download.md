# Detection 13: Certutil File Download

## Objective

Detect suspicious file download activity using `certutil.exe`.

This detection identifies use of the Windows built-in binary `certutil.exe` to download a file from a remote web server. In this lab, a harmless text file was hosted on Kali Linux and downloaded from Target-PC using `certutil.exe`. The activity generated Sysmon process creation telemetry and triggered a Windows Security alert due to suspicious LOLBin download behavior.

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Command and Control | T1105 - Ingress Tool Transfer | Target-PC attempted to download a file from a remote web server. |
| Defense Evasion | T1218 - System Binary Proxy Execution | `certutil.exe`, a trusted Windows binary, was used to perform the download. |

## Log Source

- Sysmon Operational Logs
- Windows Security / Microsoft Defender Alert
- Splunk Universal Forwarder
- Sysmon Event ID 1: Process Creation
- Sysmon Event ID 3: Network Connection, if captured
- Host: Target-PC

## Detection Logic

This detection looks for suspicious `certutil.exe` usage where the command line contains download-related arguments or URLs.

Suspicious indicators include:

```text
certutil.exe
-urlcache
-f
http://
https://
```

Attackers may abuse `certutil.exe` to download tools, payloads, scripts, or encoded content because it is a trusted Windows binary commonly present on endpoints.

## SPL Query

```spl
index=endpoint host="Target-PC" source="*Sysmon*"
("certutil.exe" OR "urlcache" OR "http://" OR "update.txt" OR "192.168.10.250")
| table _time EventCode EventID host ComputerName Image CommandLine DestinationIp DestinationPort ParentImage User _raw
| sort -_time
```

## Safe Attack Simulation

A harmless file was hosted from Kali Linux using a Python web server.

Kali command:

```bash
mkdir -p /home/kali/certutil-test
cd /home/kali/certutil-test
echo 'certutil download test file' > update.txt
python3 -m http.server 8000
```

Target-PC command:

```cmd
certutil.exe -urlcache -f http://192.168.10.250:8000/update.txt C:\Windows\Temp\update.txt
```

This simulation did **not** download malware. The hosted file was a harmless text file created for detection validation.

## Detection Result

The activity generated evidence showing suspicious `certutil.exe` download behavior.

Observed indicators:

```text
Process: certutil.exe
Argument: -urlcache -f
Remote Host: 192.168.10.250
Remote Port: 8000
Downloaded File: update.txt
Destination Path: C:\Windows\Temp\update.txt
```

Microsoft Defender also generated a threat alert because `certutil.exe` download behavior is commonly associated with LOLBin abuse.

## Analyst Thought Process

### Initial Alert Meaning

The use of `certutil.exe` with `-urlcache -f` and a remote URL is suspicious because it may indicate an attempt to download a payload using a trusted Windows binary.

### Key Questions

- Which host executed `certutil.exe`?
- Which user launched the process?
- What URL was accessed?
- What file was downloaded?
- Was the destination internal, external, approved, or suspicious?
- Did Microsoft Defender or EDR block or quarantine the activity?
- Did the downloaded file execute afterward?
- Did the same host show PowerShell, scheduled task, service creation, LSASS access, or Defender tampering activity?

### Evidence Reviewed

- Sysmon Event ID 1 process creation
- Command line containing `certutil.exe -urlcache -f`
- Destination URL and downloaded file path
- Microsoft Defender alert
- Hostname and user context
- Raw event data

## Analyst Investigation Summary

A harmless text file was hosted on Kali Linux and downloaded from Target-PC using `certutil.exe`. The command used the `-urlcache -f` arguments to retrieve `update.txt` from the Kali web server.

Splunk was used to search Sysmon telemetry for `certutil.exe`, `urlcache`, the remote Kali IP address, and the downloaded file name. Microsoft Defender also flagged the behavior as suspicious, which supports the detection value of monitoring `certutil.exe` download activity.

In a real investigation, this activity would require immediate validation of the downloaded file, URL reputation, user context, parent process, and any follow-on execution.

## Severity

High

Certutil-based downloads should be treated as high severity when the destination is unknown, external, newly observed, or followed by script execution, service creation, scheduled task creation, or credential access behavior.

## False Positive Considerations

- Authorized administrator troubleshooting
- Certificate management activity
- Internal IT scripts
- Software deployment or update workflows
- Security team testing
- Lab-generated simulation activity

This detection becomes more suspicious when `certutil.exe` is used to download files from external URLs, temporary directories, user-writable paths, or suspicious infrastructure.

## Recommended Response

- Identify the affected host and user.
- Review the full `certutil.exe` command line.
- Determine the remote URL and destination IP.
- Retrieve and hash the downloaded file if available.
- Check Microsoft Defender or EDR alerts.
- Review whether the downloaded file executed.
- Search for the same URL, IP, or file name across the environment.
- Review related process activity before and after the download.
- Block the destination if confirmed suspicious.
- Isolate the host if malicious execution occurred.
- Document the timeline and escalate if needed.

## Cleanup

After validation, the downloaded test file was removed from Target-PC if present:

```cmd
del C:\Windows\Temp\update.txt
```

The Kali Python web server was stopped with:

```text
Ctrl + C
```

## Validation Evidence

| Evidence | Screenshot |
|---|---|
| Certutil download command or Defender block alert | <img width="475" height="378" alt="13_certutil_download_command_or_defender_block" src="https://github.com/user-attachments/assets/6e5d7f77-6ef3-4544-a846-916b18bb76ec" /> |
| Raw Sysmon evidence showing certutil process creation or related telemetry | <img width="624" height="233" alt="13_raw_sysmon_certutil_process_creation" src="https://github.com/user-attachments/assets/b7911494-6acf-4dd6-a99e-8286e8d20c40" /> |
| Splunk detection query identifying certutil download indicators | <img width="624" height="238" alt="13_certutil_download_detection" src="https://github.com/user-attachments/assets/d6103fca-f049-4f66-98c0-49e74bf7afa9" /> |

## Analyst Conclusion

In my conclusion, `certutil.exe` file download activity is a high value behavior to investigate because attackers can abuse trusted Windows binaries to retrieve payloads while blending in with legitimate system activity. This lab safely simulated a certutil-based file download from a Kali-hosted web server and showed how Sysmon and Microsoft Defender can provide evidence of suspicious LOLBin usage. In a real investigation, I would review the command line, remote URL, downloaded file, user context, parent process, Defender/EDR response, and any follow-on execution to determine whether the activity was authorized or malicious.
