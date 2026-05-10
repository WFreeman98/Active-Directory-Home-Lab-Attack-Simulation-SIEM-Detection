# RDP Brute Force Detection

## Objective

Detect repeated failed RDP authentication attempts against a Windows domain workstation.

This detection identifies repeated Windows Security Event ID 4625 failures against a domain user from the same source IP. In this lab, the failed attempts were generated from Kali against Target-PC using the domain account bwaltz.

## MITRE ATT&CK Mapping

- T1110 - Brute Force
- T1021.001 - Remote Services: Remote Desktop Protocol

## Log Source

- Windows Security Event Logs
- Splunk Universal Forwarder
- Windows Event ID 4625

## Detection Logic

This detection looks for multiple failed authentication attempts against the same user from the same source IP.

In this lab, failed RDP/NLA authentication attempts appeared as Logon Type 3. Logon Type 3 is commonly associated with network-based authentication, while Logon Type 10 is associated with RemoteInteractive RDP sessions. The detection includes both Logon Type 3 and Logon Type 10 to account for RDP/NLA behavior.

## SPL Query

```spl
index=endpoint host="Target-PC" EventCode=4625
| eval source_ip=coalesce(Source_Network_Address, IpAddress, Workstation_Name)
| eval user=coalesce(Account_Name, TargetUserName)
| search user="bwaltz"
| where Logon_Type=3 OR Logon_Type=10 OR Logon_Type="3" OR Logon_Type="10"
| stats count earliest(_time) as first_seen latest(_time) as last_seen by source_ip user host ComputerName Logon_Type
| where count >= 5
| convert ctime(first_seen) ctime(last_seen)
| sort -count
```

## Attack Simulation

Hydra was used from the Kali Linux attacker machine to generate repeated RDP authentication attempts against Target-PC.

Example command:

```bash
hydra -l bwaltz -P passwords_wrong.txt rdp://192.168.10.100 -V
```

The password list contained incorrect passwords to generate failed authentication attempts.

## Analyst Thought Process

### Initial Alert Meaning

Repeated failed authentication attempts against the same domain user from the same source IP may indicate brute-force activity or password guessing.

### Key Questions

- Which account was targeted?
- What source IP generated the failures?
- Were the failures against one host or multiple hosts?
- Was the activity remote/network-based?
- Did any successful logon occur after the failed attempts?

### Evidence Reviewed

- Event ID 4625
- Target account: bwaltz
- Target host: Target-PC
- Source IP: 192.168.10.250
- Logon Type: 3
- Failure count and time range

## Analyst Investigation Summary

I began the investigation by validating the raw telemetry in Splunk to confirm the alert was based on real authentication activity. I confirmed that Target-PC generated multiple Windows Security Event ID 4625 failed logon events against the domain user bwaltz.

After confirming the event type, I reviewed the key investigation fields: the targeted account, affected host, source IP address, logon type, failure reason, and event timing. The source IP was 192.168.10.250, which matched the Kali attacker machine used during validation. The affected host was Target-PC, and the failed logons appeared as Logon Type 3, which indicates network-based authentication activity and is consistent with RDP/NLA authentication behavior.

I then moved from individual event review to pattern analysis by grouping the failed logons by source IP, user, host, and logon type. This showed repeated failed authentication attempts from the same source IP against the same user account, which supports brute-force or password-guessing behavior rather than an isolated failed login.

The next step in the investigation would be to determine whether the failed attempts were followed by a successful authentication. I would search for Windows Security Event ID 4624 from the same source IP and targeted user. If a successful logon occurred after the repeated failures, I would escalate the severity because the activity could indicate a compromised account.

I would also scope the activity by checking whether the same source IP targeted additional users or hosts. After that, I would review for post-authentication or follow-on activity such as PowerShell execution, new account creation, privileged group changes, scheduled task creation, service installation, or other persistence indicators.

Based on the investigation, the recommended response would be to investigate or block the source IP, reset the targeted account password if compromise is suspected, review RDP access controls, and document the full timeline of observed activity.

## Severity

Medium

Increase to High if followed by a successful Event ID 4624 logon from the same source IP and user.

## False Positive Considerations

- User mistyping a password repeatedly
- Misconfigured service or scheduled task
- Authorized administrator testing
- Vulnerability scanning or lab activity
- RDP/NLA authentication behavior causing repeated failures

## Recommended Response

- Identify the source IP and confirm whether it is expected.
- Review the targeted account and determine whether the activity is normal.
- Search for successful Event ID 4624 logons from the same source IP.
- Check whether other users or hosts were targeted.
- Review follow-on activity such as PowerShell execution, account creation, group changes, or persistence.
- Reset the targeted account password if compromise is suspected.
- Restrict RDP exposure and enforce MFA where possible.

## Validation Evidence

| Evidence | Screenshot |
|---|---|
| Hydra attack from Kali | <img width="500" alt="hydra_attack" src="https://github.com/user-attachments/assets/ed55f93f-fda6-420c-b93b-ca620abec180" /> |
| Raw Event ID 4625 failed logons | <img width="500" alt="raw_4625_events" src="https://github.com/user-attachments/assets/938e1144-c209-477c-9e75-e5e32162fbfd" /> |
| Splunk detection query result | <img width="500" alt="rdp_bruteforce_detection" src="https://github.com/user-attachments/assets/c0845c17-2ed6-4aef-9ae5-7537ac553b15" /> |

## Analyst Conclusion

This detection successfully identified repeated failed authentication attempts against the domain user bwaltz on Target-PC. The activity originated from 192.168.10.250, which matched the Kali attacker machine used during validation. The events were recorded as Windows Security Event ID 4625 with Logon Type 3, indicating network-based authentication behavior consistent with RDP/NLA failed logons.

The activity should be treated as suspected brute force behavior until follow up investigation confirms whether authentication was successful. The most important next step is to search for Event ID 4624 successful logons from the same source IP and user. If successful authentication is found, the investigation should shift from attempted brute force to possible account compromise.
