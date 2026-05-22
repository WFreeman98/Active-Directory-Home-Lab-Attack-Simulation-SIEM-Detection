# Detection 09: Event Log Clearing

## Objective

Detect Windows Security event log clearing activity.

This detection identifies Windows Security Event ID `1102`, which is generated when the Security audit log is cleared. In this lab, `wevtutil` was used on Target-PC to clear the Windows Security log in a controlled test.

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Defense Evasion | T1070.001 - Indicator Removal: Clear Windows Event Logs | The Windows Security audit log was cleared on Target-PC. |

## Log Source

- Windows Security Event Logs
- Splunk Universal Forwarder
- Windows Event ID 1102
- Host: Target-PC

## Detection Logic

This detection looks for Windows Security Event ID `1102`.

Event log clearing is suspicious because attackers may clear logs to remove evidence of authentication attempts, account changes, privilege changes, PowerShell activity, or other malicious behavior. In a real environment, Security log clearing should be rare and reviewed immediately.

## SPL Query

```spl
index=endpoint host="Target-PC" EventCode=1102
| table _time EventCode host ComputerName Account_Name Message
| sort -_time
```

## Attack Simulation

The Windows Security log was cleared on Target-PC using an administrator command prompt.

Command used:

```cmd
wevtutil cl Security
```

A confirmation message was also printed after the test:

```cmd
echo Security log clear test completed
```

This generated Windows Security Event ID `1102`.

## Detection Result

Splunk detected Event ID `1102` from Target-PC.

The event showed:

```text
Event ID: 1102
Host: Target-PC
ComputerName: Target-PC.corp.local
Account Name: Administrator
Message: The audit log was cleared.
```

## Analyst Thought Process

### Initial Alert Meaning

The Windows Security audit log was cleared. This may indicate defense evasion because attackers often attempt to remove evidence after authentication attacks, account changes, or privilege escalation.

### Key Questions

- Which host had its Security log cleared?
- Which account cleared the log?
- Was this action authorized?
- What activity occurred before the log was cleared?
- Were there failed logons, successful logons, account changes, or privileged group changes before the clearing event?
- Did the same user perform other suspicious actions?

### Evidence Reviewed

- Windows Security Event ID 1102
- Host: Target-PC
- Account: Administrator
- Message: The audit log was cleared
- Time of log clearing
- Command used: `wevtutil cl Security`

## Analyst Investigation Summary

I began by clearing the Windows Security log on Target-PC using `wevtutil` in an administrator command prompt. After the test was performed, I searched Splunk for Windows Security Event ID `1102`.

Splunk returned an event showing that the audit log was cleared on Target-PC. The event identified the account as `Administrator` and included the message `The audit log was cleared`.

In a real SOC investigation, this alert would require immediate review because log clearing can be used to hide previous activity. I would search for activity leading up to the log clearing event, including failed logons, successful logons, account creation, privileged group changes, suspicious PowerShell, service creation, scheduled tasks, and other persistence indicators.

## Severity

High

Clearing the Windows Security log should be treated as high severity unless it is confirmed to be authorized administrative activity.

## False Positive Considerations

- Authorized administrator maintenance
- Lab-generated testing
- System troubleshooting
- Log retention or cleanup procedures
- Security team testing

This detection becomes more suspicious when it happens after failed logons, successful remote access, account creation, privilege changes, or suspicious PowerShell activity.

## Recommended Response

- Identify the host where the Security log was cleared.
- Identify the account that cleared the log.
- Confirm whether the activity was authorized.
- Review activity before the log clearing event.
- Search for related authentication, account management, PowerShell, persistence, or lateral movement events.
- Preserve available logs from Splunk or other centralized logging systems.
- Isolate the host if malicious activity is suspected.
- Reset credentials if account compromise is suspected.
- Document the full timeline.

## Validation Evidence

| Evidence | Screenshot |
|---|---|
| wevtutil command clearing the Security log on Target-PC | <img width="566" height="151" alt="09_wevtutil_clear_security_log" src="https://github.com/user-attachments/assets/cbbfb315-d0df-4063-a97e-afcde1f0d8e1" /> |
| Raw Windows Event ID 1102 showing Security log cleared | <img width="624" height="342" alt="09_raw_1102_security_log_cleared" src="https://github.com/user-attachments/assets/03281f6c-b854-4dc6-b81b-fab7d499ec8a" /> |
| Splunk detection showing Event ID 1102 log clearing activity | <img width="624" height="181" alt="09_event_log_clearing_detection" src="https://github.com/user-attachments/assets/aac624b3-7bb6-4784-bfa3-045766d045f7" /> |

## Analyst Conclusion

This detection successfully identified Windows Security log clearing on Target-PC. The action was performed using `wevtutil cl Security`, and Splunk detected Windows Security Event ID `1102` with the message `The audit log was cleared`.

This detection is important because event log clearing is commonly associated with defense evasion. In a real investigation, the next step would be to review activity before the clearing event to determine whether an attacker attempted to hide prior actions.
