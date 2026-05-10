# Hydra RDP Brute Force Attack Simulation

## Objective

Simulate an RDP brute-force attack from the Kali Linux attacker machine against the Windows 10 domain workstation WS01.

The purpose of this test is to generate repeated failed authentication attempts that can be detected in Splunk using Windows Security Event ID 4625.

## Lab Systems

| Role | System |
|---|---|
| Attacker | Kali Linux |
| Target | Windows 10 Workstation WS01 |
| Domain Controller | Windows Server 2022 DC01 |
| SIEM | Ubuntu Server running Splunk |

## Attack Technique

This simulation represents an attacker attempting to guess valid credentials over Remote Desktop Protocol.

## MITRE ATT&CK Mapping

- T1110 - Brute Force
- T1021.001 - Remote Services: Remote Desktop Protocol

## Attack Command

```bash
hydra -l bwaltz -P passwords.txt rdp://<WS01-IP> -V
```

## Expected Telemetry

The attack should generate repeated failed logon events on the Windows workstation.

Expected Windows Security Event:

```text
Event ID: 4625
Description: An account failed to log on
Logon Type: 10
Protocol: RDP
Target Host: WS01
Target Account: bwaltz
Source IP: Kali attacker IP
```

## Splunk Validation Query

```spl
index=endpoint EventCode=4625
| eval source_ip=coalesce(src_ip, Source_Network_Address, IpAddress, Workstation_Name)
| eval user=coalesce(Account_Name, TargetUserName)
| where Logon_Type=10 OR Logon_Type="10"
| stats count earliest(_time) as first_seen latest(_time) as last_seen by source_ip user host
| where count >= 10
| convert ctime(first_seen) ctime(last_seen)
| sort -count
```

## Analyst Validation

The detection is considered successful if Splunk shows multiple failed RDP logon attempts from the Kali source IP against WS01 and the target user account.

## Analyst Thought Process

A single failed login may be normal user error. Repeated failed RDP logons from the same source IP against the same account in a short time window suggests brute-force behavior.

The next investigation step is to search for Event ID 4624 successful logons from the same source IP and target account to determine whether the attacker gained access.

## Screenshots

| Screenshot | Status |
|---|---|
| Hydra attack running from Kali | Pending |
| Splunk detection result | Pending |
| Raw Windows Event ID 4625 details | Pending |
