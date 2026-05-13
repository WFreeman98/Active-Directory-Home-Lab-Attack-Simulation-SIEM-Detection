# Detection 02: Successful Login After Failures

## Objective

Detect repeated failed RDP authentication attempts followed by a successful logon from the same source IP against the same domain user account.

This detection builds on the RDP brute-force detection by identifying whether failed authentication attempts were followed by a successful login. In a real SOC environment, this pattern may indicate that an attacker successfully guessed, obtained, or reused valid credentials.

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Credential Access | T1110 - Brute Force | Multiple Event ID 4625 failed logons were generated against the same domain user from the same source IP. |
| Initial Access / Defense Evasion / Persistence / Privilege Escalation | T1078 - Valid Accounts | A successful Event ID 4624 logon occurred after repeated failed attempts, indicating possible valid credential use. |
| Lateral Movement | T1021.001 - Remote Services: Remote Desktop Protocol | The successful authentication occurred over RDP and appeared as Logon Type 10. |

## Log Source

- Windows Security Event Logs
- Splunk Universal Forwarder
- Windows Event ID 4625
- Windows Event ID 4624

## Detection Logic

This detection looks for multiple failed logons followed by a successful logon from the same source IP against the same user account.

Failed logons alone may indicate attempted brute force. Failed logons followed by a successful logon are more serious because they may indicate possible account compromise.

In this lab, the failed RDP/NLA authentication attempts appeared as Logon Type 3, while the successful RDP session appeared as Logon Type 10.

## SPL Query

```spl
index=endpoint host="Target-PC" (EventCode=4625 OR EventCode=4624) (TargetUserName="bwaltz" OR Account_Name="bwaltz")
| where Source_Network_Address="192.168.10.250"
| eval user=coalesce(TargetUserName, Account_Name)
| eval failure_time=if(EventCode=4625,_time,null())
| eval success_time=if(EventCode=4624,_time,null())
| stats count(eval(EventCode=4625)) as failure_count count(eval(EventCode=4624)) as success_count earliest(failure_time) as first_failure latest(failure_time) as last_failure earliest(success_time) as first_success values(Logon_Type) as logon_types by Source_Network_Address user host ComputerName
| where failure_count >= 5 AND success_count >= 1 AND first_success > first_failure
| convert ctime(first_failure) ctime(last_failure) ctime(first_success)
| sort -failure_count
```

## Attack Simulation

Hydra was used from the Kali Linux attacker machine to generate repeated failed RDP authentication attempts against Target-PC.

Example command:

```bash
hydra -l bwaltz -P passwords_wrong.txt rdp://192.168.10.100 -V -t 1
```

After the failed attempts, a successful RDP login was performed using the same domain account.

Example command:

```bash
xfreerdp /v:192.168.10.100 /d:CORP /u:bwaltz /cert:ignore
```

The successful login password was not included in the command or documentation.

## Detection Result

The detection identified repeated failed authentication attempts against the domain user `bwaltz` from source IP `192.168.10.250`, followed by successful logons from the same source IP.

The failed attempts appeared as Logon Type 3, while the successful RDP logon appeared as Logon Type 10. This supports the conclusion that the same source system generated failed RDP authentication attempts and later successfully authenticated to Target-PC.

## Analyst Thought Process

### Initial Alert Meaning

Repeated failed logons followed by a successful logon may indicate that an attacker guessed or obtained valid credentials.

### Key Questions

- Which account had repeated failed logons?
- What source IP generated the failed attempts?
- Did the same source IP later authenticate successfully?
- Did the successful login occur after the failed attempts?
- Was the activity remote/RDP-based?
- Was there any post-login activity after the successful authentication?

### Evidence Reviewed

- Event ID 4625 failed logons
- Event ID 4624 successful logons
- Target account: bwaltz
- Target host: Target-PC
- Source IP: 192.168.10.250
- Failed logon type: 3
- Successful logon type: 10
- Failure count and success count
- First failure time and first success time

## Analyst Investigation Summary

I began by validating the failed authentication activity in Splunk. Target-PC generated multiple Windows Security Event ID 4625 failed logons against the domain user `bwaltz` from source IP `192.168.10.250`.

After confirming the failed logons, I performed a successful RDP login using the same domain account from the same Kali source system. Splunk then showed Event ID 4624 successful logons for `bwaltz` from `192.168.10.250`.

I correlated the failed and successful events by user, source IP, host, and event timing. The successful login occurred after the failed attempts, which changed the investigation from simple brute-force activity to possible account compromise.

The failed logons appeared as Logon Type 3, consistent with RDP/NLA authentication behavior. The successful RDP session appeared as Logon Type 10, which indicates a RemoteInteractive logon.

## Severity

High

This alert is higher severity than failed logons alone because the failed authentication attempts were followed by a successful login from the same source IP and user.

## False Positive Considerations

- A user repeatedly mistyping their password before successfully logging in
- Help desk or administrator testing
- A user correcting an outdated saved password
- Lab-generated authentication testing
- Automated authentication attempts followed by a valid login

This detection becomes more suspicious when the source IP is unusual, the failure count is high, the activity occurs outside normal hours, or the same source targets multiple users.

## Recommended Response

- Confirm whether the successful login was authorized.
- Identify and investigate the source IP.
- Review the affected account for suspicious activity.
- Check for additional successful logons from the same source.
- Search for post-login activity such as PowerShell execution, new account creation, group changes, scheduled tasks, or new services.
- Reset the affected account password if compromise is suspected.
- Restrict RDP access and enforce MFA where possible.
- Document the full timeline of failed and successful authentication events.

## Validation Evidence

| Evidence | Screenshot |
|---|---|
| Hydra failed RDP attempts from Kali | <img width="624" height="457" alt="02_hydra_failures" src="https://github.com/user-attachments/assets/4a5c1002-a465-4011-97af-fb280d5619c6" /> |
| Raw Splunk timeline showing 4625 failures followed by 4624 success | <img width="624" height="299" alt="02_raw_4625_4624_events" src="https://github.com/user-attachments/assets/6525d5ea-80a1-422f-92be-101a6c202894" /> |
| Splunk correlation showing successful login after failures | <img width="624" height="246" alt="02_successful_login_after_failures_detection" src="https://github.com/user-attachments/assets/f797905a-b5db-4f0c-b16c-ba6c8dfb8d95" /> |

## Analyst Conclusion

This detection successfully identified repeated failed RDP authentication attempts followed by successful logons for the domain user `bwaltz` on Target-PC. The activity originated from `192.168.10.250`, which matched the Kali attacker machine used during validation.

The detection is more severe than failed logons alone because the same source IP later authenticated successfully. In a real SOC investigation, this would require validation of whether the successful login was authorized and review of the affected account and host for post-login activity.
